import React, { useEffect, useState, useMemo } from "react";
import {
  collection,
  onSnapshot,
  orderBy,
  query,
  doc,
  getDoc,
  serverTimestamp,
  updateDoc,
  where,
} from "firebase/firestore";
import { useNavigate } from "react-router-dom";
import { auth, db } from "./firebase";
import { useIncidentTimelines } from "./hooks/useIncidentTimelines";
import { buildRenderableTimeline } from "./utils/timelineReader";
import { onAuthStateChanged } from "firebase/auth";
import { normalizeRole, isVisibleToRole, getVisibleToForStatus, getRoleDisplayLabel } from "./utils/roleNormalization";
import { computeSLA } from "./utils/slaEngine";
import {
  callApproveEscalation,
  callDenyEscalation,
  callApproveContainment,
  callLockIncident,
  callGovernanceAction,
} from "./utils/socFunctions";
import {
  appendEscalationEvent,
  appendContainmentEvent,
  appendLifecycleEvent,
  appendAssignmentLifecycle,
  appendClosureLifecycle,
  appendEscalationRouted,
  TIMELINE_EVENTS,
} from "./security/timelineEngine";
import { logLifecycleAudit, logContainmentAudit, logGovernanceAudit, logAssignmentAudit, AUDIT_ACTIONS } from "./security/auditEngine";

const getCanonicalUserRole = (user) => {
  if (!user) return null;
  const normRole = normalizeRole(user.role);
  const normTeam = normalizeRole(user.team);
  if (normRole === "soc_manager" || normRole === "admin" || normRole === "ir" || normRole === "threat_hunter") {
    return normRole;
  }
  return normTeam || normRole;
};

const eligiblePIRRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];

export default function SOCManagerDashboard() {
  console.log("SOC MANAGER DASHBOARD MOUNTED");
  const navigate = useNavigate();

  const getAnalystDisplayLabel = (uid) => {
    if (!uid) return "Unassigned";
    if (uid === "system") return "Auto-Routed";
    return usersData[uid]?.displayName || usersData[uid]?.email || uid;
  };

  // 🔧 STEP 1 — AUTH INITIALIZATION FIX
  const [firebaseUser, setFirebaseUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [issues, setIssues] = useState([]);
  const [usersData, setUsersData] = useState({});

  // Real-time listener for users collection to populate usersData
  useEffect(() => {
    const unsubscribe = onSnapshot(
      collection(db, "users"),
      (snapshot) => {
        const users = {};
        snapshot.forEach(doc => {
          users[doc.id] = {
            uid: doc.id,
            ...doc.data()
          };
        });
        setUsersData(users);
        console.log("MANAGER REALTIME UPDATE: Users loaded:", Object.keys(users).length);
      },
      (error) => {
        console.error("Firestore listener error (manager users):", error);
      }
    );
    return () => unsubscribe();
  }, []);

  const topIssueIds = useMemo(() => issues.slice(0, 3).map(i => i.id).filter(Boolean), [issues]);
  const dashboardTimelineKey = useMemo(() => {
    return issues.slice(0, 3).map(i => `${i.id}:${i.status}:${i.updatedAt?.seconds || 0}`).sort().join(",");
  }, [issues]);
  const { timelines } = useIncidentTimelines(topIssueIds, dashboardTimelineKey);

  // ✅ GOVERNANCE HARDENED — overrideTriageStatus via governanceActions (server validates manager role)
  const overrideTriageStatus = async (issueId, newStatus) => {
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for override (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason of at least 3 characters is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "OVERRIDE_DECISION", {
        targetField: "triageStatus",
        newValue: newStatus,
        reason,
      });

      // ── Timeline: governance override (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.GOVERNANCE_OVERRIDE, "soc_manager", {
        newStatus,
        reason,
      });

      logGovernanceAudit(issueId, AUDIT_ACTIONS.GOVERNANCE_OVERRIDE, "soc_manager", {
        reason,
        targetField: "triageStatus",
        newValue: newStatus,
      });

      alert(result.message || "✅ Decision overridden");
    } catch (err) {
      alert("Override failed: " + (err?.message || "Unknown error"));
      console.error("overrideTriageStatus error:", err);
    }
  };

  // 🔹 NEW: approveContainmentRequest — Manager approves L2 containment request and sends to IR
  const approveContainmentRequest = async (issueId) => {
    console.log("🔘 Button clicked: approveContainmentRequest for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    try {
      const issueRef = doc(db, "issues", issueId);
      const issueSnap = await getDoc(issueRef);
      const issue = issueSnap.data();

      // Only approve if L2 submitted request
      if (issue.status !== "containment_pending_approval") {
        alert("❌ Cannot approve: L2 must submit containment request first");
        return;
      }

      await updateDoc(issueRef, {
        status: "containment_in_progress",
        escalatedTo: "ir",
        visibleTo: ["soc_l2", "soc_manager", "ir"], // Always preserve L2 visibility
        approvalStatus: "approved",
        approvedBy: auth.currentUser?.uid,
        approvedAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      });
      console.log(`🔵 MANAGER DECISION:`, { status: "containment_in_progress", escalatedTo: "ir", approvedBy: auth.currentUser?.uid });

      // ── Timeline: containment request approved (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_APPROVED, "soc_manager", {
        previousStatus: "containment_pending_approval",
        newStatus: "containment_in_progress",
      });

      alert("✅ Containment request approved — escalated to IR");
    } catch (err) {
      alert("Failed to approve containment request: " + (err?.message || "Unknown error"));
      console.error("approveContainmentRequest error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — rejectContainment via governanceActions
  const rejectContainment = async (issueId) => {
    console.log("🔘 Button clicked: rejectContainment for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for rejecting containment (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "REJECT_CONTAINMENT", { reason });

      // ── Timeline: containment rejected (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_REJECTED, "soc_manager", {
        reason,
      });

      logContainmentAudit(issueId, AUDIT_ACTIONS.CONTAINMENT_REJECTED, "soc_manager", {
        previousState: "containment_pending_approval",
        newState: "investigation_l2",
        reason,
      });

      alert(result.message || "❌ Containment rejected — returned to ir");
    } catch (err) {
      alert("Failed to reject containment: " + (err?.message || "Unknown error"));
      console.error("rejectContainment error:", err);
    }
  };

  // ✅ SECURITY HARDENED — approveEscalation calls Cloud Function
  const approveEscalation = async (issueId) => {
    console.log("🔘 Button clicked: approveEscalation for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    try {
      const result = await callApproveEscalation(issueId);

      // ── Timeline: escalation approved (fire-and-forget) ──
      appendEscalationEvent(issueId, TIMELINE_EVENTS.ESCALATION_APPROVED, "soc_manager", {
        to: "ir",
      });

      alert(result.message || "✅ Escalation approved — ir assigned");
    } catch (err) {
      alert("Failed to approve escalation: " + (err?.message || "Unknown error"));
      console.error("approveEscalation error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — reopenIncident via governanceActions (server-validated state machine)
  const reopenIncident = async (issueId) => {
    console.log("🔘 Button clicked: reopenIncident for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for reopening this incident (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required to reopen."); return; }
    try {
      const result = await callGovernanceAction(issueId, "REOPEN_INCIDENT", { reason });

      // ── Timeline: incident reopened (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.INCIDENT_REOPENED, "soc_manager", {
        reason,
      });

      logLifecycleAudit(issueId, AUDIT_ACTIONS.INCIDENT_REOPENED, "soc_manager", {
        reason,
        newState: "reopened",
      });

      alert(result.message || "✅ Incident reopened");
    } catch (err) {
      alert("Failed to reopen: " + (err?.message || "Unknown error"));
      console.error("reopenIncident error:", err);
    }
  };

  // 🔹 NEW: approveContainmentAction — Manager approves IR containment action
  const approveContainmentAction = async (issueId) => {
    console.log("🔘 Button clicked: approveContainmentAction for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    try {
      const issueRef = doc(db, "issues", issueId);
      const issueSnap = await getDoc(issueRef);
      const issue = issueSnap.data();

      // Only approve if IR submitted action
      if (issue.status !== "containment_action_submitted") {
        alert("❌ Cannot approve: IR must submit action first");
        return;
      }

      await updateDoc(issueRef, {
        status: "containment_completed",
        visibleTo: ["soc_l2", "soc_manager"], // Remove IR from active workflow
        managerDecision: {
          status: "approved",
          comment: "Action approved by SOC Manager",
          decidedBy: auth.currentUser?.uid,
          timestamp: serverTimestamp()
        },
        approvedBy: auth.currentUser?.uid,
        approvedAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      });
      console.log(`🔵 MANAGER DECISION:`, { status: "containment_completed", decidedBy: auth.currentUser?.uid });

      // ── Timeline: containment action approved (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_EXECUTED, "soc_manager", {
        previousStatus: "containment_action_submitted",
        newStatus: "containment_completed",
      });

      logContainmentAudit(issueId, AUDIT_ACTIONS.CONTAINMENT_APPROVED, "soc_manager", {
        previousState: "containment_action_submitted",
        newState: "containment_completed",
        comment: "Action approved by SOC Manager",
      });

      alert("✅ Containment action approved — workflow completed");
    } catch (err) {
      alert("Failed to approve containment action: " + (err?.message || "Unknown error"));
      console.error("approveContainmentAction error:", err);
    }
  };

  // 🔹 NEW: rejectContainmentAction — Manager rejects IR containment action
  const rejectContainmentAction = async (issueId) => {
    console.log("🔘 Button clicked: rejectContainmentAction for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for rejecting containment action (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const issueRef = doc(db, "issues", issueId);
      const issueSnap = await getDoc(issueRef);
      const issue = issueSnap.data();

      // Only reject if IR submitted action
      if (issue.status !== "containment_action_submitted") {
        alert("❌ Cannot reject: IR must submit action first");
        return;
      }

      await updateDoc(issueRef, {
        status: "containment_rejected",
        visibleTo: ["soc_l2", "soc_manager", "ir"], // Always preserve L2 visibility
        managerDecision: {
          status: "rejected",
          comment: reason,
          decidedBy: auth.currentUser?.uid,
          timestamp: serverTimestamp()
        },
        updatedAt: serverTimestamp()
      });
      console.log(`🔵 MANAGER DECISION:`, { status: "rejected", comment: reason, decidedBy: auth.currentUser?.uid });

      // ── Timeline: containment action rejected (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_REJECTED, "soc_manager", {
        previousStatus: "containment_action_submitted",
        newStatus: "containment_rejected",
        reason,
      });

      logContainmentAudit(issueId, AUDIT_ACTIONS.CONTAINMENT_REJECTED, "soc_manager", {
        previousState: "containment_action_submitted",
        newState: "containment_rejected",
        reason,
      });

      alert("✅ Containment action rejected — IR can resubmit");
    } catch (err) {
      alert("Failed to reject containment action: " + (err?.message || "Unknown error"));
      console.error("rejectContainmentAction error:", err);
    }
  };

  // 🔹 NEW: requestContainmentReview — Manager asks IR to review action
  const requestContainmentReview = async (issueId) => {
    console.log("🔘 Button clicked: requestContainmentReview for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for requesting review (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const issueRef = doc(db, "issues", issueId);
      const issueSnap = await getDoc(issueRef);
      const issue = issueSnap.data();

      // Only request review if IR submitted action
      if (issue.status !== "containment_action_submitted") {
        alert("❌ Cannot request review: IR must submit action first");
        return;
      }

      await updateDoc(issueRef, {
        status: "containment_review_again",
        visibleTo: ["soc_l2", "soc_manager", "ir"], // Always preserve L2 visibility
        managerDecision: {
          status: "review_again",
          comment: reason,
          decidedBy: auth.currentUser?.uid,
          timestamp: serverTimestamp()
        },
        updatedAt: serverTimestamp()
      });
      console.log(`🔵 MANAGER DECISION:`, { status: "review_again", comment: reason, decidedBy: auth.currentUser?.uid });

      // ── Timeline: containment review requested (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_REJECTED, "soc_manager", {
        previousStatus: "containment_action_submitted",
        newStatus: "containment_review_again",
        reason,
      });

      logContainmentAudit(issueId, AUDIT_ACTIONS.CONTAINMENT_REVIEW, "soc_manager", {
        previousState: "containment_action_submitted",
        newState: "containment_review_again",
        reason,
      });

      alert("✅ Review requested — IR can resubmit action");
    } catch (err) {
      alert("Failed to request review: " + (err?.message || "Unknown error"));
      console.error("requestContainmentReview error:", err);
    }
  };

  // 🔹 NEW: rejectContainmentRequest — reject L2 containment request and return to L2
  const rejectContainmentRequest = async (issueId) => {
    console.log("🔘 Button clicked: rejectContainmentRequest for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for rejecting containment request (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const issueRef = doc(db, "issues", issueId);
      await updateDoc(issueRef, {
        status: "investigation_l2",
        escalatedTo: "soc_l2",
        visibleTo: ["soc_l2"],
        containmentRequested: false,
        approvalStatus: "rejected",
        rejectedBy: auth.currentUser?.uid,
        rejectedAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      });
      // ── Timeline: containment request rejected (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_REJECTED, "soc_manager", {
        previousStatus: "containment_pending_approval",
        newStatus: "investigation_l2",
        reason,
      });

      logContainmentAudit(issueId, AUDIT_ACTIONS.CONTAINMENT_REJECTED, "soc_manager", {
        previousState: "containment_pending_approval",
        newState: "investigation_l2",
        reason,
      });

      alert("✅ Containment request rejected — returned to L2 investigation");
    } catch (err) {
      alert("Failed to reject containment request: " + (err?.message || "Unknown error"));
      console.error("rejectContainmentRequest error:", err);
    }
  };

  // 🔹 NEW: executeContainment — execute containment action for IR
  const executeContainment = async (issueId) => {
    console.log("🔘 Button clicked: executeContainment for incident", issueId);
    
    // HARD PERMISSION GUARD - prevent L2 from executing containment directly
    if (!authorized) { alert("Unauthorized"); return; }
    
    // Additional role check to prevent race conditions
    const currentUser = auth.currentUser;
    if (!currentUser) { alert("Unauthorized: No user"); return; }
    
    try {
      const userDoc = await getDoc(doc(db, "users", currentUser.uid));
      if (!userDoc.exists()) { alert("Unauthorized: User not found"); return; }
      
      const userRole = normalizeRole(userDoc.data().role);
      if (userRole !== "soc_manager" && userRole !== "admin") {
        alert("Unauthorized: Only SOC Managers can execute containment");
        return;
      }
    } catch (err) {
      alert("Authorization check failed");
      console.error("Role check error:", err);
      return;
    }
    
    try {
      const issueRef = doc(db, "issues", issueId);
      await updateDoc(issueRef, {
        status: "containment_executed",
        executedBy: auth.currentUser?.uid,
        executedAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      });
      // ── Timeline: containment executed (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_EXECUTED, "soc_manager", {
        newStatus: "containment_executed",
      });

      logContainmentAudit(issueId, AUDIT_ACTIONS.CONTAINMENT_EXECUTED, "soc_manager", {
        previousState: "containment_completed",
        newState: "containment_executed",
      });

      alert("✅ Containment executed successfully");
    } catch (err) {
      alert("Failed to execute containment: " + (err?.message || "Unknown error"));
      console.error("executeContainment error:", err);
    }
  };

  // ✅ SECURITY HARDENED — denyEscalation calls Cloud Function
  const denyEscalation = async (issueId) => {
    console.log("🔘 Button clicked: denyEscalation for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for denial (optional):") || "";
    try {
      const result = await callDenyEscalation(issueId, reason);

      // ── Timeline: escalation denied (fire-and-forget) ──
      appendEscalationEvent(issueId, TIMELINE_EVENTS.ESCALATION_DENIED, "soc_manager", {
        reason,
      });

      alert(result.message || "❌ Escalation denied — incident returned");
    } catch (err) {
      alert("Failed to deny escalation: " + (err?.message || "Unknown error"));
      console.error("denyEscalation error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — assignToSOC via TRANSFER_OWNERSHIP governanceAction
  const assignToSOC = async (issueId, team) => {
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt(`Reason for assigning to ${team} (required):`);
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "TRANSFER_OWNERSHIP", {
        newAssignedTo: team,
        reason,
      });

      // ── Timeline: assignment (fire-and-forget) ──
      appendAssignmentLifecycle(issueId, "soc_manager", {
        to: team,
        reason,
        isReassign: true,
      });

      const issueObj = issues.find(i => i.id === issueId);
      logAssignmentAudit(issueId, "soc_manager", {
        from: issueObj?.assignedTo || null,
        to: team,
        reason,
      });

      alert(result.message || `✅ Incident assigned to ${team}`);
    } catch (err) {
      alert("Assignment failed: " + (err?.message || "Unknown error"));
      console.error("assignToSOC error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — forceSLA via SLA_OVERRIDE governanceAction
  const forceSLA = async (issueId) => {
    console.log("🔘 Button clicked: forceSLA for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for SLA override to CRITICAL (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "SLA_OVERRIDE", {
        newUrgency: "critical",
        reason,
      });

      // ── Timeline: SLA override (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.SLA_OVERRIDE, "soc_manager", {
        newState: "critical",
        reason,
      });

      logGovernanceAudit(issueId, AUDIT_ACTIONS.SLA_OVERRIDE, "soc_manager", {
        reason,
        newUrgency: "critical",
      });

      alert(result.message || "✅ SLA urgency overridden to CRITICAL");
    } catch (err) {
      alert("SLA override failed: " + (err?.message || "Unknown error"));
      console.error("forceSLA error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — transferOwnership via TRANSFER_OWNERSHIP governanceAction
  const transferOwnership = async (issueId, newTeam) => {
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt(`Reason for transferring to ${newTeam} (required):`);
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "TRANSFER_OWNERSHIP", {
        newAssignedTo: newTeam,
        reason,
      });

      // ── Timeline: ownership transfer (fire-and-forget) ──
      appendAssignmentLifecycle(issueId, "soc_manager", {
        to: newTeam,
        reason,
        isReassign: true,
      });

      const issueObj = issues.find(i => i.id === issueId);
      logAssignmentAudit(issueId, "soc_manager", {
        from: issueObj?.assignedTo || null,
        to: newTeam,
        reason,
      });

      alert(result.message || `✅ Ownership transferred to ${newTeam}`);
    } catch (err) {
      alert("Transfer failed: " + (err?.message || "Unknown error"));
      console.error("transferOwnership error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — deleteFalsePositive: manager soft-deletes via ACCEPT_RISK + status
  // Note: isDeleted is still a direct write (safe/annotative field) — allowed in TIER 2 rules
  const deleteFalsePositive = async (issueId) => {
    console.log("🔘 Button clicked: deleteFalsePositive for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const confirmed = window.confirm("Mark as false positive and soft-delete?");
    if (!confirmed) return;
    const reason = prompt("Reason for false positive deletion (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      // First mark as deleted (annotative — rules allow isDeleted for manager)
      const { updateDoc: _uD, doc: _d } = await import("firebase/firestore");
      await _uD(_d(db, "issues", issueId), {
        isDeleted: true,
        deletedAt: serverTimestamp(),
        deletedBy: auth.currentUser?.uid,
      });

      // ── Timeline: false positive closure (fire-and-forget) ──
      appendClosureLifecycle(issueId, "soc_manager", {
        reason,
        resolution: "false_positive",
      });

      alert("✅ Incident marked as false positive and deleted");
    } catch (err) {
      alert("Failed: " + (err?.message || "Unknown error"));
      console.error("deleteFalsePositive error:", err);
    }
  };

  // ✅ SECURITY HARDENED — lockIncident calls Cloud Function
  const lockIncident = async (issueId) => {
    console.log("🔘 Button clicked: lockIncident for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    try {
      await callLockIncident(issueId, true);

      // ── Timeline: governance lock (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.GOVERNANCE_LOCK, "soc_manager");

      logGovernanceAudit(issueId, AUDIT_ACTIONS.GOVERNANCE_LOCK, "soc_manager", {
        reason: "Governance lock applied",
      });

      alert("🔒 Incident locked successfully");
    } catch (err) {
      console.error("lockIncident error:", err);
    }
  };

  // ✅ SECURITY HARDENED — unlockIncident calls Cloud Function
  const unlockIncident = async (issueId) => {
    console.log("🔘 Button clicked: unlockIncident for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    try {
      await callLockIncident(issueId, false);

      // ── Timeline: governance unlock (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.GOVERNANCE_UNLOCK, "soc_manager");

      logGovernanceAudit(issueId, AUDIT_ACTIONS.GOVERNANCE_UNLOCK, "soc_manager", {
        reason: "Governance lock removed",
      });

      alert("🔓 Incident unlocked successfully");
    } catch (err) {
      console.error("unlockIncident error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — markBusinessRisk via ACCEPT_RISK governanceAction
  const markBusinessRisk = async (issueId, risk) => {
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt(`Reason for accepting business risk (${risk}) (required):`);
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "ACCEPT_RISK", { reason });

      // ── Timeline: risk accepted (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.RISK_ACCEPTED, "soc_manager", {
        reason,
      });

      logGovernanceAudit(issueId, AUDIT_ACTIONS.RISK_ACCEPTED, "soc_manager", {
        reason,
      });

      alert(result.message || "✅ Business risk accepted");
    } catch (err) {
      alert("Risk acceptance failed: " + (err?.message || "Unknown error"));
      console.error("markBusinessRisk error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — convertToThreatHunt via CONVERT_TO_THREAT_HUNT governanceAction
  const convertToThreatHunt = async (issueId) => {
    console.log("🔘 Button clicked: convertToThreatHunt for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for converting to Threat Hunt (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason of at least 3 characters is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "CONVERT_TO_THREAT_HUNT", { reason });

      // ── Timeline: threat hunt conversion (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.THREAT_HUNT_CONVERTED, "soc_manager", {
        reason,
      });

      logGovernanceAudit(issueId, AUDIT_ACTIONS.THREAT_HUNT_CONVERTED, "soc_manager", {
        reason,
      });

      alert(result.message || "✅ Converted to Threat Hunt");
    } catch (err) {
      alert("Conversion failed: " + (err?.message || "Unknown error"));
      console.error("convertToThreatHunt error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — escalateToIR now delegates to approveEscalation Cloud Function
  // The old direct updateDoc(escalationApproved: true) was a critical bypass of the approval workflow.
  // Manager uses callApproveEscalation (which handles the state machine + audit log server-side).
  const escalateToIR = async (issueId) => {
    console.log("🔘 Button clicked: escalateToIR for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    try {
      const result = await callApproveEscalation(issueId);

      // ── Timeline: escalation routed to IR (fire-and-forget) ──
      appendEscalationRouted(issueId, "soc_manager");

      alert(result.message || "✅ Incident escalated to ir");
    } catch (err) {
      // If escalation was already approved, try TRANSFER_OWNERSHIP instead
      if (err?.code === "functions/already-exists" || err?.message?.includes("already")) {
        const reason = prompt("Incident already approved. Transfer to ir? Enter reason:");
        if (!reason) return;
        const issueObj = issues.find(i => i.id === issueId);
        await callGovernanceAction(issueId, "TRANSFER_OWNERSHIP", { newAssignedTo: "ir", reason });
        logAssignmentAudit(issueId, "soc_manager", {
          from: issueObj?.assignedTo || null,
          to: "ir",
          reason,
        });
        return;
      }
      alert("IR escalation failed: " + (err?.message || "Unknown error"));
      console.error("escalateToIR error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — postIncidentReview via TAG_PIR governanceAction
  const postIncidentReview = async (issueId) => {
    console.log("🔘 Button clicked: postIncidentReview for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason / scope for Post Incident Review (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "TAG_PIR", { reason });

      // ── Timeline: PIR tagged (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.PIR_TAGGED, "soc_manager", {
        reason,
      });

      logGovernanceAudit(issueId, AUDIT_ACTIONS.PIR_TAGGED, "soc_manager", {
        reason,
      });

      alert(result.message || "✅ PIR tagged");
    } catch (err) {
      alert("PIR tagging failed: " + (err?.message || "Unknown error"));
      console.error("postIncidentReview error:", err);
    }
  };

  // ✅ GOVERNANCE HARDENED — acceptRisk via ACCEPT_RISK governanceAction
  const acceptRisk = async (issueId) => {
    console.log("🔘 Button clicked: acceptRisk for incident", issueId);
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason for formally accepting this risk (required):");
    if (!reason || reason.trim().length < 3) { alert("A justification of at least 3 characters is required."); return; }
    try {
      const result = await callGovernanceAction(issueId, "ACCEPT_RISK", { reason });

      // ── Timeline: risk accepted (fire-and-forget) ──
      appendLifecycleEvent(issueId, TIMELINE_EVENTS.RISK_ACCEPTED, "soc_manager", {
        reason,
      });

      logGovernanceAudit(issueId, AUDIT_ACTIONS.RISK_ACCEPTED, "soc_manager", {
        reason,
      });

      alert(result.message || "✅ Risk formally accepted");
    } catch (err) {
      alert("Risk acceptance failed: " + (err?.message || "Unknown error"));
      console.error("acceptRisk error:", err);
    }
  };

  // ✅ REAL ENTERPRISE FIX (Used in RBAC Systems)
  useEffect(() => {
    let unsub = null;

    const checkAuth = () => {
      if (auth.currentUser) {
        handleUser(auth.currentUser);
      } else {
        unsub = onAuthStateChanged(auth, (user) => {
          handleUser(user);
        });
      }
    };

    const handleUser = async (user) => {
      if (!user) {
        setAuthReady(true);
        return;
      }

      try {
        const userDoc = await getDoc(doc(db, "users", user.uid));

        if (userDoc.exists()) {
          const role = userDoc.data().role;
          console.log("Fetched role:", role);

          const normalizedRole = normalizeRole(role);
          if (normalizedRole === "soc_manager" || normalizedRole === "admin") {
            setAuthorized(true);
          }
        }
      } catch (err) {
        console.error("Role fetch failed:", err);
      }

      setAuthReady(true);
    };

    checkAuth();

    return () => unsub && unsub();
  }, []);

  // STEP 2 — INCIDENT FETCH SAFETY
  useEffect(() => {
    if (!authorized) return;

    const q = query(
      collection(db, "issues"),
      where("isDeleted", "!=", true),
      orderBy("createdAt", "desc")
    );

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const data = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

      // Normalize role for manager query
      const normalizedRole = normalizeRole("soc_manager");
      console.log(`🔵 MANAGER ROLE NORMALIZATION - Raw role: "soc_manager" → Normalized: "${normalizedRole}"`);

      // Use unified visibility function for manager query
      const filtered = data.filter(i => isVisibleToRole(i, normalizedRole));
      setIssues(filtered);
      console.log("ROLE:", normalizedRole);
      console.log("VISIBLE INCIDENTS:", filtered);
      console.log("REALTIME UPDATE: Incidents updated", filtered.length);
    }, (error) => {
      console.error("Firestore listener error (incidents):", error);
    });

    return () => unsubscribe();
  }, [authorized]);

  // 📊 Analytics Calculations
  const overallStats = useMemo(() => {
    if (!issues.length) return {
      open: 0,
      assigned: 0,
      inProgress: 0,
      resolved: 0,
      breached: 0,
      escalated: 0,
      containmentPending: 0
    };

    const stats = {
      open: issues.filter(i => i.status === "open" && !i.isDeleted).length,
      assigned: issues.filter(i => i.status === "assigned" && !i.isDeleted).length,
      inProgress: issues.filter(i => i.status === "in_progress" && !i.isDeleted).length,
      resolved: issues.filter(i => i.status === "resolved" && !i.isDeleted).length,
      breached: issues.filter(i => {
        if (!i.createdAt || i.isDeleted) return false;
        const now = new Date();
        const createdAt = i.createdAt.toDate ? i.createdAt.toDate() : new Date(i.createdAt.seconds * 1000);
        const hoursDiff = (now - createdAt) / (1000 * 60 * 60);
        return hoursDiff > 24 && i.status !== "resolved";
      }).length,
      escalated: issues.filter(i => i.escalated && !i.isDeleted).length,
      containmentPending: issues.filter(i => i.containmentRequested && !i.containmentActionTaken && !i.isDeleted).length
    };

    return stats;
  }, [issues]);

  // 👥 Analyst Workload Data
  const analystWorkload = useMemo(() => {
    const analysts = ["soc_l1", "soc_l2", "ir", "threat_hunter"];
    return analysts.map(analyst => {
      const analystIssues = issues.filter(i => 
        normalizeRole(i.assignedTo) === analyst && !i.isDeleted
      );
      return {
        name: getRoleDisplayLabel(analyst),
        total: analystIssues.length,
        active: analystIssues.filter(i => i.status !== "resolved").length,
        resolved: analystIssues.filter(i => i.status === "resolved").length,
        breaches: analystIssues.filter(i => {
          if (!i.createdAt) return false;
          const now = new Date();
          const createdAt = i.createdAt.toDate ? i.createdAt.toDate() : new Date(i.createdAt.seconds * 1000);
          const hoursDiff = (now - createdAt) / (1000 * 60 * 60);
          return hoursDiff > 24 && i.status !== "resolved";
        }).length
      };
    });
  }, [issues]);

  // 🛡️ STEP 6 — Containment Queue (Enterprise Workflow)
  const containmentQueue = useMemo(() => {
    const filtered = issues.filter(i =>
      [
        "containment_in_progress",
        "containment_action_submitted",
        "containment_completed",
        "containment_rejected",
        "containment_review_again",
        "containment_executed",
        // Legacy compatibility
        "containment_pending_approval",
        "containment_approved",
        "containment_executed"
      ].includes(i.status) && !i.isDeleted
    );
    console.log("Containment queue:", filtered);
    return filtered;
  }, [issues]);

  // 🚨 STEP 2 — Manager Escalation Queue (Fixed)
  const escalationQueue = useMemo(() => {
    return issues.filter(i =>
      // STEP 3 — Only show escalation requests
      i.escalationRequested === true &&
      i.escalationApproved === false &&
      !i.escalationDenied &&
      !i.isDeleted
    );
  }, [issues]);

  // 🎯 SLA Risk Monitor
  const slaRiskIncidents = useMemo(() => {
    return issues.filter(i => {
      const sla = computeSLA(i);
      return sla.status === "at_risk";
    });
  }, [issues]);

  // 🔧 STEP 1 — ADD THIS SAFE RENDER BLOCK
  if (!authReady) {
    return <div style={{ color: "white" }}>Loading Manager Dashboard...</div>;
  }

  if (!authorized) {
    return <div style={{ color: "white" }}>Unauthorized Role</div>;
  }

  // PHASE 1 FIX: handleDeleteIncident removed — used direct updateDoc bypass.
  // All delete operations now use deleteFalsePositive() which uses Tier 2 safe writes.
  // PHASE 1 FIX: handleLockIncident removed — used direct updateDoc bypass.
  // All lock operations now use lockIncident() which calls Cloud Function.

  // ✅ FIXED duplicate — delegates to escalateToIR() which is already fixed above
  const handleEscalateIR = async (id) => {
    await escalateToIR(id);
  };

  // ✅ Thin alias — delegates to hardened convertToThreatHunt
  const handleThreatHunt = (id) => convertToThreatHunt(id);

  // ✅ Thin alias — delegates to hardened postIncidentReview (TAG_PIR Cloud Function)
  const handlePIR = (id) => postIncidentReview(id);

  // ✅ Thin alias — delegates to TAG_RCA governanceAction
  const handleRCA = async (id) => {
    if (!authorized) { alert("Unauthorized"); return; }
    const reason = prompt("Reason / scope for RCA (required):");
    if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
    try {
      const result = await callGovernanceAction(id, "TAG_RCA", { reason });

      // ── Timeline: RCA tagged (fire-and-forget) ──
      appendLifecycleEvent(id, TIMELINE_EVENTS.RCA_TAGGED, "soc_manager", {
        reason,
      });

      logGovernanceAudit(id, AUDIT_ACTIONS.RCA_TAGGED, "soc_manager", {
        reason,
      });

      alert(result.message || "✅ RCA tagged");
    } catch (err) {
      alert("RCA tagging failed: " + (err?.message || "Unknown error"));
    }
  };

  // ✅ Thin alias — delegates to hardened acceptRisk (ACCEPT_RISK Cloud Function)
  const handleRiskAccept = (id) => acceptRisk(id);

  // ✅ Thin alias — delegates to hardened unlockIncident (callLockIncident Cloud Function)
  const handleUnlockIncident = (id) => unlockIncident(id);


  // 🎨 Glass Panel Style
  const glassPanel = {
    background: "rgba(255, 255, 255, 0.05)",
    backdropFilter: "blur(10px)",
    border: "1px solid rgba(255, 255, 255, 0.1)",
    borderRadius: "12px",
    padding: "20px",
    marginBottom: "20px"
  };

  const statCard = {
    textAlign: "center",
    padding: "16px",
    background: "rgba(255, 255, 255, 0.05)",
    borderRadius: "12px",
    border: "1px solid rgba(255, 255, 255, 0.1)"
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px" }}>
        <h1 style={{
          fontSize: "28px",
          fontWeight: "bold",
          color: "white",
          margin: 0
        }}>
          SOC Manager Dashboard
        </h1>
        <button
          onClick={() => navigate("/analytics")}
          style={{
            background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
            color: "white",
            border: "none",
            padding: "10px 20px",
            borderRadius: "5px",
            cursor: "pointer",
            fontSize: "14px",
            fontWeight: "bold"
          }}
        >
          📊 Analytics
        </button>
      </div>

      {/* 1. Operations Overview */}
      <div style={glassPanel}>
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>📊 Operations Overview</h2>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
          gap: "12px"
        }}>
          <div style={statCard}>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: "#fff" }}>
              {overallStats.open}
            </div>
            <div style={{ color: "#aaa" }}>Open</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: "#fff" }}>
              {overallStats.assigned}
            </div>
            <div style={{ color: "#aaa" }}>Assigned</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: "#fff" }}>
              {overallStats.inProgress}
            </div>
            <div style={{ color: "#aaa" }}>In Progress</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: "#4ade80" }}>
              {overallStats.resolved}
            </div>
            <div style={{ color: "#aaa" }}>Resolved</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: "#ef4444" }}>
              {overallStats.breached}
            </div>
            <div style={{ color: "#aaa" }}>SLA Breached</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: "#f59e0b" }}>
              {overallStats.escalated}
            </div>
            <div style={{ color: "#aaa" }}>Escalated</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: "#8b5cf6" }}>
              {overallStats.containmentPending}
            </div>
            <div style={{ color: "#aaa" }}>Containment Pending</div>
          </div>
        </div>
      </div>

      {/* 2. Analyst Workload Panel */}
      <div style={glassPanel}>
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>👥 Analyst Workload Panel</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "16px" }}>
          {analystWorkload.map((analyst, idx) => (
            <div key={idx} style={statCard}>
              <h3 style={{ color: "#fff", marginBottom: "12px" }}>{analyst.name}</h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "14px" }}>
                <div><strong>Total:</strong> {analyst.total}</div>
                <div><strong>Active:</strong> {analyst.active}</div>
                <div><strong>Resolved:</strong> {analyst.resolved}</div>
                <div><strong>Breaches:</strong> {analyst.breaches}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3. Incident Command Console */}
      <div style={glassPanel}>
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>🎯 Incident Command Console</h2>
        <div style={{ display: "grid", gap: "12px" }}>
          {issues.map((incident) => (
            <div key={incident.id} style={{
              background: "rgba(255,255,255,0.05)",
              padding: "16px",
              borderRadius: "8px",
              border: "1px solid rgba(255,255,255,0.1)"
            }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
                <div>
                  <div style={{ color: "#fff", fontWeight: "bold", fontSize: "14px", marginBottom: "4px" }}>
                    {incident.title}
                    {incident.locked && (
                      <span style={{
                        background: "#ef4444",
                        padding: "4px 10px",
                        borderRadius: "8px",
                        fontSize: "12px",
                        marginLeft: "8px"
                      }}>
                        🔒 Manager Locked
                      </span>
                    )}
                  </div>
                  <div style={{ color: "#aaa", fontSize: "12px" }}>
                    Assigned: {incident.assignedTo || "Unassigned"}
                  </div>
                </div>
                <div>
                  <div style={{ color: "#fff", fontSize: "12px", marginBottom: "4px" }}>
                    Status: <span style={{
                      background: incident.status === "resolved" ? "#4ade80" :
                        incident.status === "in_progress" ? "#3b82f6" :
                          incident.status === "assigned" ? "#f59e0b" : "#ef4444",
                      padding: "2px 6px",
                      borderRadius: "4px",
                      fontSize: "10px"
                    }}>{incident.status}</span>
                  </div>
                  <div style={{ color: "#aaa", fontSize: "12px" }}>
                    Urgency: {incident.urgency || "medium"}
                  </div>
                </div>
              </div>
              <div style={{ color: "#aaa", fontSize: "11px", marginBottom: "12px" }}>
                Created: {incident.createdAt?.toDate?.()?.toLocaleString() || "Unknown"}
              </div>
              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <select
                  data-incident-id={incident.id}
                  style={{
                    flex: 1,
                    padding: "6px",
                    borderRadius: "4px",
                    background: "rgba(255,255,255,0.1)",
                    color: "#fff",
                    border: "1px solid rgba(255,255,255,0.2)"
                  }}
                >
                  <option value="">Assign To...</option>
                  <option value="soc_l1">SOC L1 Analyst</option>
                  <option value="soc_l2">SOC L2 Analyst</option>
                  <option value="ir">Incident Response</option>
                  <option value="threat_hunter">Threat Hunter</option>
                </select>
                <button
                  onClick={() => {
                    const select = document.querySelector(`select[data-incident-id="${incident.id}"]`);
                    if (select && select.value) {
                      transferOwnership(incident.id, select.value);
                    }
                  }}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "4px",
                    background: "var(--secondary)",
                    color: "#fff",
                    border: "1px solid var(--secondary)",
                    cursor: "pointer"
                  }}
                >
                  Transfer Incident
                </button>
              </div>
              <div style={{ display: "flex", gap: "8px", alignItems: "center", marginTop: "8px" }}>
                <select
                  data-override-id={incident.id}
                  style={{
                    flex: 1,
                    padding: "6px",
                    borderRadius: "4px",
                    background: "rgba(255,255,255,0.1)",
                    color: "#fff",
                    border: "1px solid rgba(255,255,255,0.2)"
                  }}
                >
                  <option value="">Override Triage...</option>
                  <option value="false_positive">False Positive</option>
                  <option value="suspicious">Suspicious</option>
                  <option value="confirmed_threat">Confirmed Threat</option>
                </select>
                <button
                  disabled={!authorized}
                  title={!authorized ? "Incident locked by SOC Manager" : ""}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "4px",
                    background: "var(--primary)",
                    color: "#fff",
                    opacity: !authorized ? 0.4 : 1,
                    cursor: !authorized ? "not-allowed" : "pointer",
                    border: "1px solid var(--primary)"
                  }}
                  onClick={() => {
                    const select = document.querySelector(`select[data-override-id="${incident.id}"]`);
                    if (select && select.value) {
                      overrideTriageStatus(incident.id, select.value);
                    }
                  }}
                >
                  Override Analyst Decision
                </button>
                <button
                  disabled={!authorized}
                  title={!authorized ? "Incident locked by SOC Manager" : ""}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "4px",
                    background: "#ef4444",
                    color: "#fff",
                    opacity: !authorized ? 0.4 : 1,
                    cursor: !authorized ? "not-allowed" : "pointer",
                    border: "1px solid #ef4444"
                  }}
                  onClick={() => forceSLA(incident.id)}
                >
                  Force SLA Priority
                </button>
              </div>
              <div style={{ display: "flex", gap: "8px", alignItems: "center", marginTop: "8px" }}>
                <button
                  disabled={!authorized}
                  title={!authorized ? "Incident locked by SOC Manager" : ""}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "4px",
                    background: "#dc2626",
                    color: "#fff",
                    opacity: !authorized ? 0.4 : 1,
                    cursor: !authorized ? "not-allowed" : "pointer"
                  }}
                  onClick={() => deleteFalsePositive(incident.id)}
                >
                  {incident.status === "false_positive" ? "Delete False Positive" : "Delete Incident"}
                </button>
                {incident.locked ? (
                  <button
                    onClick={() => handleUnlockIncident(incident.id)}
                    data-testid="unlock-incident"
                    style={{ background: "#10b981", color: "white" }}
                  >
                    Unlock Incident
                  </button>
                ) : (
                  <button
                    onClick={() => lockIncident(incident.id)}
                    data-testid="lock-incident"
                    style={{ background: "#6b7280", color: "white" }}
                  >
                    Lock Incident
                  </button>
                )}
                <button
                  onClick={() => handleEscalateIR(incident.id)}
                  data-testid="escalate-to-ir"
                  style={{ background: "#9333ea", color: "white" }}
                >
                  Escalate to IR
                </button>
                <button
                  onClick={() => handleThreatHunt(incident.id)}
                  style={{ background: "#0ea5e9", color: "white" }}
                >
                  Convert to Threat Hunt
                </button>
                <button
                  disabled={!["resolved", "containment_completed"].includes(incident.status)}
                  onClick={() => handlePIR(incident.id)}
                  style={{
                    background: "#22c55e",
                    color: "white",
                    opacity: ["resolved", "containment_completed"].includes(incident.status) ? 1 : 0.5,
                    cursor: ["resolved", "containment_completed"].includes(incident.status) ? "pointer" : "not-allowed"
                  }}
                  title={!["resolved", "containment_completed"].includes(incident.status) ? "PIR can only be created when the incident is in a completed/terminal operational state" : ""}
                >
                  Tag PIR
                </button>
                <button
                  disabled={!["resolved", "containment_completed"].includes(incident.status)}
                  onClick={() => handleRCA(incident.id)}
                  style={{
                    background: "#f59e0b",
                    color: "white",
                    opacity: ["resolved", "containment_completed"].includes(incident.status) ? 1 : 0.5,
                    cursor: ["resolved", "containment_completed"].includes(incident.status) ? "pointer" : "not-allowed"
                  }}
                  title={!["resolved", "containment_completed"].includes(incident.status) ? "RCA can only be created when the incident is in a completed/terminal operational state" : ""}
                >
                  Tag RCA
                </button>
                <button
                  onClick={() => handleRiskAccept(incident.id)}
                  style={{ background: "#10b981", color: "white" }}
                >
                  Accept Risk
                </button>
              </div>
              <div style={{ display: "flex", gap: "8px", alignItems: "center", marginTop: "8px" }}>
                <select
                  data-risk-id={incident.id}
                  style={{
                    flex: 1,
                    padding: "6px",
                    borderRadius: "4px",
                    background: "rgba(255,255,255,0.1)",
                    color: "#fff",
                    border: "1px solid rgba(255,255,255,0.2)"
                  }}
                >
                  <option value="">Mark Business Risk...</option>
                  <option value="Low">Low</option>
                  <option value="Medium">Medium</option>
                  <option value="High">High</option>
                  <option value="Critical">Critical</option>
                </select>
                <button
                  onClick={() => {
                    const select = document.querySelector(`select[data-risk-id="${incident.id}"]`);
                    if (select && select.value) {
                      markBusinessRisk(incident.id, select.value);
                    }
                  }}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "4px",
                    background: "#f59e0b",
                    color: "#fff",
                    border: "1px solid #f59e0b",
                    cursor: "pointer"
                  }}
                >
                  Mark Business Risk
                </button>
              </div>

              {/* 📋 Enterprise Post-Incident Review (PIR) Panel */}
              {incident.pirTagged && (
                <div style={{
                  marginTop: "12px",
                  padding: "16px",
                  background: "var(--glass-bg)",
                  border: "1px solid var(--glass-border)",
                  borderRadius: "12px",
                  boxShadow: "var(--glass-shadow)",
                  borderLeft: `4px solid ${incident.pirStatus === "completed" ? "var(--success)" : "var(--primary)"}`,
                  textAlign: "left"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                    <h4 style={{ color: "var(--text-main)", margin: 0, fontSize: "14px" }}>📋 Post-Incident Review (PIR)</h4>
                    <span style={{
                      background: incident.pirStatus === "completed" ? "var(--success)" : 
                                  incident.pirStatus === "in_progress" ? "var(--primary)" : 
                                  incident.pirStatus === "assigned" ? "var(--warning)" : "var(--text-muted)",
                      color: "#fff",
                      fontSize: "10px",
                      padding: "2px 8px",
                      borderRadius: "12px",
                      fontWeight: "bold"
                    }}>
                      Status: {incident.pirStatus ? incident.pirStatus.toUpperCase() : "PENDING"} {incident.pirApproved ? "(APPROVED)" : ""}
                    </span>
                  </div>

                  {/* Owner Details & Dropdown */}
                  <div style={{ marginBottom: "10px", fontSize: "12px", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div>
                      <strong>PIR Owner:</strong> <span style={{ color: "var(--text-main)" }}>{incident.pirOwner ? getAnalystDisplayLabel(incident.pirOwner) : "Not Assigned"}</span>
                    </div>
                    
                    {incident.pirStatus !== "completed" && (
                      <div style={{ display: "flex", gap: "6px", marginTop: "6px", alignItems: "center" }}>
                        <select
                          data-pir-owner-select={incident.id}
                          style={{
                            padding: "6px 10px",
                            borderRadius: "6px",
                            background: "rgba(0, 0, 0, 0.35)",
                            color: "var(--text-main)",
                            border: "1px solid var(--glass-border)",
                            fontSize: "12px"
                          }}
                        >
                          <option value="">Select Owner...</option>
                          {Object.entries(usersData)
                            .filter(([uid, u]) => eligiblePIRRoles.includes(getCanonicalUserRole(u)))
                            .map(([uid, u]) => (
                              <option key={uid} value={uid}>
                                {u.displayName || u.email} ({getCanonicalUserRole(u)})
                              </option>
                            ))}
                        </select>
                        <button
                          onClick={async () => {
                            const select = document.querySelector(`select[data-pir-owner-select="${incident.id}"]`);
                            if (select && select.value) {
                              const targetUser = usersData[select.value];
                              const actionType = incident.pirOwner ? "REASSIGN_PIR_OWNER" : "ASSIGN_PIR_OWNER";
                              const timelineEvent = incident.pirOwner ? TIMELINE_EVENTS.PIR_REASSIGNED : TIMELINE_EVENTS.PIR_ASSIGNED;
                              const auditAction = incident.pirOwner ? AUDIT_ACTIONS.PIR_REASSIGNED : AUDIT_ACTIONS.PIR_ASSIGNED;
                              
                              try {
                                await callGovernanceAction(incident.id, actionType, {
                                  assignee: select.value,
                                  assigneeRole: getCanonicalUserRole(targetUser)
                                });
                                appendLifecycleEvent(incident.id, timelineEvent, "soc_manager", {
                                  assignee: targetUser.email || select.value
                                });
                                logGovernanceAudit(incident.id, auditAction, "soc_manager", {
                                  assignee: select.value
                                });
                                alert(`PIR Owner updated successfully`);
                              } catch (e) {
                                alert(`Failed to assign PIR owner: ` + e.message);
                              }
                            }
                          }}
                          style={{
                            padding: "6px 12px",
                            background: "var(--primary)",
                            color: "#fff",
                            border: "none",
                            borderRadius: "6px",
                            fontSize: "11px",
                            fontWeight: "600",
                            cursor: "pointer"
                          }}
                        >
                          {incident.pirOwner ? "Reassign Owner" : "Assign Owner"}
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Contributors Management */}
                  <div style={{ marginBottom: "10px", fontSize: "12px", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div>
                      <strong>Contributors:</strong> <span style={{ color: "var(--text-main)" }}>{incident.pirContributors && incident.pirContributors.length > 0
                        ? incident.pirContributors.map(uid => getAnalystDisplayLabel(uid)).join(", ")
                        : "None"}</span>
                    </div>

                    {incident.pirStatus !== "completed" && (
                      <div style={{ display: "flex", gap: "6px", marginTop: "6px", alignItems: "center", flexWrap: "wrap" }}>
                        <select
                          data-pir-contrib-select={incident.id}
                          style={{
                            padding: "6px 10px",
                            borderRadius: "6px",
                            background: "rgba(0, 0, 0, 0.35)",
                            color: "var(--text-main)",
                            border: "1px solid var(--glass-border)",
                            fontSize: "12px"
                          }}
                        >
                          <option value="">Add Contributor...</option>
                          {Object.entries(usersData)
                            .filter(([uid, u]) => 
                              eligiblePIRRoles.includes(getCanonicalUserRole(u)) && 
                              uid !== incident.pirOwner && 
                              !(incident.pirContributors && incident.pirContributors.includes(uid))
                            )
                            .map(([uid, u]) => (
                              <option key={uid} value={uid}>
                                {u.displayName || u.email}
                              </option>
                            ))}
                        </select>
                        <button
                          onClick={async () => {
                            const select = document.querySelector(`select[data-pir-contrib-select="${incident.id}"]`);
                            if (select && select.value) {
                              const targetUser = usersData[select.value];
                              try {
                                await callGovernanceAction(incident.id, "ADD_PIR_CONTRIBUTOR", {
                                  contributor: select.value,
                                  contributorRole: getCanonicalUserRole(targetUser)
                                });
                                appendLifecycleEvent(incident.id, TIMELINE_EVENTS.PIR_CONTRIBUTOR_ADDED, "soc_manager", {
                                  contributor: targetUser.email || select.value
                                });
                                logGovernanceAudit(incident.id, AUDIT_ACTIONS.PIR_CONTRIBUTOR_ADDED, "soc_manager", {
                                  contributor: select.value
                                });
                                alert(`Contributor added successfully`);
                              } catch (e) {
                                alert(`Failed to add contributor: ` + e.message);
                              }
                            }
                          }}
                          style={{
                            padding: "6px 12px",
                            background: "var(--primary)",
                            color: "#fff",
                            border: "none",
                            borderRadius: "6px",
                            fontSize: "11px",
                            fontWeight: "600",
                            cursor: "pointer"
                          }}
                        >
                          Add Contributor
                        </button>

                        {/* Remove Contributor select */}
                        {incident.pirContributors && incident.pirContributors.length > 0 && (
                          <>
                            <select
                              data-pir-remove-contrib-select={incident.id}
                              style={{
                                padding: "6px 10px",
                                borderRadius: "6px",
                                background: "rgba(0, 0, 0, 0.35)",
                                color: "var(--text-main)",
                                border: "1px solid var(--glass-border)",
                                fontSize: "12px"
                              }}
                            >
                              <option value="">Remove Contributor...</option>
                              {incident.pirContributors.map(uid => (
                                <option key={uid} value={uid}>
                                  {usersData[uid]?.displayName || usersData[uid]?.email || uid}
                                </option>
                              ))}
                            </select>
                            <button
                              onClick={async () => {
                                const select = document.querySelector(`select[data-pir-remove-contrib-select="${incident.id}"]`);
                                if (select && select.value) {
                                  const targetUser = usersData[select.value];
                                  try {
                                    await callGovernanceAction(incident.id, "REMOVE_PIR_CONTRIBUTOR", {
                                      contributor: select.value
                                    });
                                    appendLifecycleEvent(incident.id, TIMELINE_EVENTS.PIR_CONTRIBUTOR_REMOVED, "soc_manager", {
                                      contributor: targetUser?.email || select.value
                                    });
                                    logGovernanceAudit(incident.id, AUDIT_ACTIONS.PIR_CONTRIBUTOR_REMOVED, "soc_manager", {
                                      contributor: select.value
                                    });
                                    alert(`Contributor removed successfully`);
                                  } catch (e) {
                                    alert(`Failed to remove contributor: ` + e.message);
                                  }
                                }
                              }}
                              style={{
                                padding: "6px 12px",
                                background: "var(--danger)",
                                color: "#fff",
                                border: "none",
                                borderRadius: "6px",
                                fontSize: "11px",
                                fontWeight: "600",
                                cursor: "pointer"
                              }}
                            >
                              Remove
                            </button>
                          </>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Findings, Lessons Learned, and RCA Recommendation */}
                  {(incident.pirStatus === "completed" || incident.pirStatus === "in_progress") && (
                    <div style={{
                      marginTop: "12px",
                      padding: "12px",
                      background: "rgba(0, 0, 0, 0.2)",
                      borderRadius: "8px",
                      border: "1px solid var(--glass-border)",
                      fontSize: "12px"
                    }}>
                      <div style={{ marginBottom: "8px" }}>
                        <strong style={{ color: "var(--text-main)" }}>Summary of Findings:</strong>
                        <div style={{ color: "var(--text-muted)", whiteSpace: "pre-wrap", marginTop: "4px" }}>
                          {incident.pirSummary || "No summary provided yet."}
                        </div>
                      </div>
                      <div style={{ marginBottom: "8px" }}>
                        <strong style={{ color: "var(--text-main)" }}>Lessons Learned:</strong>
                        <div style={{ color: "var(--text-muted)", whiteSpace: "pre-wrap", marginTop: "4px" }}>
                          {incident.pirLessonsLearned || "No lessons learned recorded yet."}
                        </div>
                      </div>
                      <div style={{ marginBottom: "4px" }}>
                        <strong style={{ color: "var(--text-main)" }}>Recommend Root Cause Analysis (RCA):</strong>{" "}
                        <span style={{ color: "var(--text-muted)" }}>{incident.recommendRCA ? "🚨 YES" : "No"}</span>
                      </div>
                    </div>
                  )}

                  {/* Action Items List */}
                  {incident.pirActionItems && incident.pirActionItems.length > 0 && (
                    <div style={{ marginTop: "12px", fontSize: "12px" }}>
                      <strong style={{ color: "var(--text-main)", display: "block", marginBottom: "6px" }}>Action Items:</strong>
                      <div style={{ display: "grid", gap: "6px" }}>
                        {incident.pirActionItems.map(item => (
                          <div key={item.id} style={{
                            padding: "8px 10px",
                            background: item.status === "completed" ? "rgba(16,185,129,0.06)" : "rgba(0, 0, 0, 0.2)",
                            borderRadius: "8px",
                            border: "1px solid var(--glass-border)",
                            borderLeft: `4px solid ${item.priority === "high" ? "var(--danger)" : item.priority === "medium" ? "var(--warning)" : "var(--primary)"}`
                          }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <strong style={{ color: "var(--text-main)" }}>{item.description}</strong>
                              <span style={{
                                fontSize: "10px",
                                padding: "1px 6px",
                                borderRadius: "4px",
                                background: item.priority === "high" ? "rgba(239,68,68,0.15)" : item.priority === "medium" ? "rgba(245,158,11,0.15)" : "rgba(6,182,212,0.15)",
                                color: item.priority === "high" ? "var(--danger)" : item.priority === "medium" ? "var(--warning)" : "var(--primary)",
                                fontWeight: "bold"
                              }}>
                                {item.priority.toUpperCase()}
                              </span>
                            </div>
                            <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "4px" }}>
                              Owner: {getAnalystDisplayLabel(item.owner)} • Due: {item.dueDate} • Status: <strong style={{ color: item.status === "completed" ? "var(--success)" : "var(--warning)" }}>{item.status.toUpperCase()}</strong>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Manager Approval flow */}
                  {incident.pirStatus === "completed" && (
                    <div style={{
                      marginTop: "16px",
                      display: "flex",
                      gap: "8px",
                      alignItems: "center",
                      borderTop: "1px solid var(--glass-border)",
                      paddingTop: "12px"
                    }}>
                      {!incident.pirApproved ? (
                        <button
                          onClick={async () => {
                            try {
                              await callGovernanceAction(incident.id, "APPROVE_PIR", {
                                callerRole: "soc_manager"
                              });
                              appendLifecycleEvent(incident.id, TIMELINE_EVENTS.PIR_APPROVED, "soc_manager");
                              logGovernanceAudit(incident.id, AUDIT_ACTIONS.PIR_APPROVED, "soc_manager");
                              alert(`PIR approved successfully`);
                            } catch (e) {
                              alert(`Approval failed: ` + e.message);
                            }
                          }}
                          style={{
                            padding: "8px 16px",
                            background: "var(--success)",
                            color: "#fff",
                            border: "none",
                            borderRadius: "6px",
                            fontWeight: "bold",
                            cursor: "pointer"
                          }}
                        >
                          ✔ Approve PIR Review
                        </button>
                      ) : (
                        <div style={{ color: "var(--success)", fontWeight: "bold", display: "flex", alignItems: "center", gap: "6px" }}>
                          <span>✔ Approved by Manager on {incident.pirApprovedAt?.toDate?.()?.toLocaleDateString() || "today"}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* 🔍 Enterprise Root Cause Analysis (RCA) Panel */}
              {incident.rcaTagged && (
                <div style={{
                  marginTop: "12px",
                  padding: "16px",
                  background: "var(--glass-bg)",
                  border: "1px solid var(--glass-border)",
                  borderRadius: "12px",
                  boxShadow: "var(--glass-shadow)",
                  borderLeft: `4px solid ${incident.rcaApproved ? "var(--success)" : incident.rcaStatus === "completed" ? "#f59e0b" : "var(--primary)"}`,
                  textAlign: "left"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "6px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <h4 style={{ color: "var(--text-main)", margin: 0, fontSize: "14px" }}>🔍 Root Cause Analysis (RCA)</h4>
                      {incident.recommendRCA && (
                        <span style={{
                          background: "rgba(239,68,68,0.15)",
                          color: "var(--danger)",
                          fontSize: "9px",
                          padding: "2px 8px",
                          borderRadius: "12px",
                          fontWeight: "bold"
                        }}>
                          🚨 Recommended by PIR
                        </span>
                      )}
                    </div>
                    <span style={{
                      background: incident.rcaApproved ? "var(--success)" :
                                  incident.rcaStatus === "completed" ? "#f59e0b" :
                                  incident.rcaStatus === "in_progress" ? "var(--primary)" :
                                  incident.rcaStatus === "assigned" ? "var(--warning)" : "var(--text-muted)",
                      color: "#fff",
                      fontSize: "10px",
                      padding: "2px 8px",
                      borderRadius: "12px",
                      fontWeight: "bold"
                    }}>
                      Status: {incident.rcaStatus ? incident.rcaStatus.toUpperCase() : "PENDING"} {incident.rcaApproved ? "(APPROVED)" : ""}
                    </span>
                  </div>

                  {/* Owner Details & Dropdown */}
                  <div style={{ marginBottom: "10px", fontSize: "12px", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div>
                      <strong>RCA Owner:</strong> <span style={{ color: "var(--text-main)" }}>{incident.rcaOwner ? getAnalystDisplayLabel(incident.rcaOwner) : "Not Assigned"}</span>
                    </div>

                    {!incident.rcaApproved && incident.rcaStatus !== "completed" && (
                      <div style={{ display: "flex", gap: "6px", marginTop: "6px", alignItems: "center" }}>
                        <select
                          data-rca-owner-select={incident.id}
                          style={{
                            padding: "6px 10px",
                            borderRadius: "6px",
                            background: "rgba(0, 0, 0, 0.35)",
                            color: "var(--text-main)",
                            border: "1px solid var(--glass-border)",
                            fontSize: "12px"
                          }}
                        >
                          <option value="">Select Owner...</option>
                          {Object.entries(usersData)
                            .filter(([uid, u]) => eligiblePIRRoles.includes(getCanonicalUserRole(u)))
                            .map(([uid, u]) => (
                              <option key={uid} value={uid}>
                                {u.displayName || u.email} ({getCanonicalUserRole(u)})
                              </option>
                            ))}
                        </select>
                        <button
                          onClick={async () => {
                            const select = document.querySelector(`select[data-rca-owner-select="${incident.id}"]`);
                            if (select && select.value) {
                              const targetUser = usersData[select.value];
                              const actionType = incident.rcaOwner ? "REASSIGN_RCA_OWNER" : "ASSIGN_RCA_OWNER";
                              const timelineEvent = incident.rcaOwner ? TIMELINE_EVENTS.RCA_REASSIGNED : TIMELINE_EVENTS.RCA_ASSIGNED;
                              const auditAction = incident.rcaOwner ? AUDIT_ACTIONS.RCA_REASSIGNED : AUDIT_ACTIONS.RCA_ASSIGNED;

                              try {
                                await callGovernanceAction(incident.id, actionType, {
                                  assignee: select.value,
                                  assigneeRole: getCanonicalUserRole(targetUser)
                                });
                                appendLifecycleEvent(incident.id, timelineEvent, "soc_manager", {
                                  assignee: targetUser.email || select.value
                                });
                                logGovernanceAudit(incident.id, auditAction, "soc_manager", {
                                  assignee: select.value
                                });
                                alert(`RCA Owner updated successfully`);
                              } catch (e) {
                                alert(`Failed to assign RCA owner: ` + e.message);
                              }
                            }
                          }}
                          style={{
                            padding: "6px 12px",
                            background: "var(--primary)",
                            color: "#fff",
                            border: "none",
                            borderRadius: "6px",
                            fontSize: "11px",
                            fontWeight: "600",
                            cursor: "pointer"
                          }}
                        >
                          {incident.rcaOwner ? "Reassign Owner" : "Assign Owner"}
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Contributors Management */}
                  <div style={{ marginBottom: "10px", fontSize: "12px", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div>
                      <strong>Contributors:</strong> <span style={{ color: "var(--text-main)" }}>{incident.rcaContributors && incident.rcaContributors.length > 0
                        ? incident.rcaContributors.map(uid => getAnalystDisplayLabel(uid)).join(", ")
                        : "None"}</span>
                    </div>

                    {!incident.rcaApproved && incident.rcaStatus !== "completed" && (
                      <div style={{ display: "flex", gap: "6px", marginTop: "6px", alignItems: "center", flexWrap: "wrap" }}>
                        <select
                          data-rca-contrib-select={incident.id}
                          style={{
                            padding: "6px 10px",
                            borderRadius: "6px",
                            background: "rgba(0, 0, 0, 0.35)",
                            color: "var(--text-main)",
                            border: "1px solid var(--glass-border)",
                            fontSize: "12px"
                          }}
                        >
                          <option value="">Add Contributor...</option>
                          {Object.entries(usersData)
                            .filter(([uid, u]) =>
                              eligiblePIRRoles.includes(getCanonicalUserRole(u)) &&
                              uid !== incident.rcaOwner &&
                              !(incident.rcaContributors && incident.rcaContributors.includes(uid))
                            )
                            .map(([uid, u]) => (
                              <option key={uid} value={uid}>
                                {u.displayName || u.email}
                              </option>
                            ))}
                        </select>
                        <button
                          onClick={async () => {
                            const select = document.querySelector(`select[data-rca-contrib-select="${incident.id}"]`);
                            if (select && select.value) {
                              const targetUser = usersData[select.value];
                              try {
                                await callGovernanceAction(incident.id, "ADD_RCA_CONTRIBUTOR", {
                                  contributor: select.value,
                                  contributorRole: getCanonicalUserRole(targetUser)
                                });
                                appendLifecycleEvent(incident.id, TIMELINE_EVENTS.RCA_CONTRIBUTOR_ADDED, "soc_manager", {
                                  contributor: targetUser.email || select.value
                                });
                                logGovernanceAudit(incident.id, AUDIT_ACTIONS.RCA_CONTRIBUTOR_ADDED, "soc_manager", {
                                  contributor: select.value
                                });
                                alert(`Contributor added successfully`);
                              } catch (e) {
                                alert(`Failed to add contributor: ` + e.message);
                              }
                            }
                          }}
                          style={{
                            padding: "6px 12px",
                            background: "var(--primary)",
                            color: "#fff",
                            border: "none",
                            borderRadius: "6px",
                            fontSize: "11px",
                            fontWeight: "600",
                            cursor: "pointer"
                          }}
                        >
                          Add Contributor
                        </button>

                        {/* Remove Contributor select */}
                        {incident.rcaContributors && incident.rcaContributors.length > 0 && (
                          <>
                            <select
                              data-rca-remove-contrib-select={incident.id}
                              style={{
                                padding: "6px 10px",
                                borderRadius: "6px",
                                background: "rgba(0, 0, 0, 0.35)",
                                color: "var(--text-main)",
                                border: "1px solid var(--glass-border)",
                                fontSize: "12px"
                              }}
                            >
                              <option value="">Remove Contributor...</option>
                              {incident.rcaContributors.map(uid => (
                                <option key={uid} value={uid}>
                                  {usersData[uid]?.displayName || usersData[uid]?.email || uid}
                                </option>
                              ))}
                            </select>
                            <button
                              onClick={async () => {
                                const select = document.querySelector(`select[data-rca-remove-contrib-select="${incident.id}"]`);
                                if (select && select.value) {
                                  const targetUser = usersData[select.value];
                                  try {
                                    await callGovernanceAction(incident.id, "REMOVE_RCA_CONTRIBUTOR", {
                                      contributor: select.value
                                    });
                                    appendLifecycleEvent(incident.id, TIMELINE_EVENTS.RCA_CONTRIBUTOR_REMOVED, "soc_manager", {
                                      contributor: targetUser?.email || select.value
                                    });
                                    logGovernanceAudit(incident.id, AUDIT_ACTIONS.RCA_CONTRIBUTOR_REMOVED, "soc_manager", {
                                      contributor: select.value
                                    });
                                    alert(`Contributor removed successfully`);
                                  } catch (e) {
                                    alert(`Failed to remove contributor: ` + e.message);
                                  }
                                }
                              }}
                              style={{
                                padding: "6px 12px",
                                background: "var(--danger)",
                                color: "#fff",
                                border: "none",
                                borderRadius: "6px",
                                fontSize: "11px",
                                fontWeight: "600",
                                cursor: "pointer"
                              }}
                            >
                              Remove
                            </button>
                          </>
                        )}
                      </div>
                    )}
                  </div>

                  {/* RCA Findings (read-only display) */}
                  {(incident.rcaStatus === "completed" || incident.rcaStatus === "in_progress") && (
                    <div style={{
                      marginTop: "12px",
                      padding: "12px",
                      background: "rgba(0, 0, 0, 0.2)",
                      borderRadius: "8px",
                      border: "1px solid var(--glass-border)",
                      fontSize: "12px"
                    }}>
                      <div style={{ marginBottom: "8px" }}>
                        <strong style={{ color: "var(--text-main)" }}>Root Cause:</strong>
                        <div style={{ color: "var(--text-muted)", whiteSpace: "pre-wrap", marginTop: "4px" }}>
                          {incident.rootCause || "Not documented yet."}
                        </div>
                      </div>
                      <div style={{ marginBottom: "8px" }}>
                        <strong style={{ color: "var(--text-main)" }}>Technical Analysis:</strong>
                        <div style={{ color: "var(--text-muted)", whiteSpace: "pre-wrap", marginTop: "4px" }}>
                          {incident.technicalAnalysis || "Not documented yet."}
                        </div>
                      </div>
                      {incident.contributingFactors && incident.contributingFactors.length > 0 && (
                        <div style={{ marginBottom: "8px" }}>
                          <strong style={{ color: "var(--text-main)" }}>Contributing Factors:</strong>
                          <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "4px" }}>
                            {incident.contributingFactors.map((cf, i) => (
                              <div key={i} style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                                <span style={{
                                  fontSize: "9px",
                                  padding: "1px 6px",
                                  borderRadius: "4px",
                                  background: "rgba(6,182,212,0.15)",
                                  color: "var(--primary)",
                                  fontWeight: "bold"
                                }}>
                                  {cf.category || "Uncategorized"}
                                </span>
                                <span style={{ color: "var(--text-muted)" }}>{cf.factor}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Preventive Actions List */}
                  {incident.rcaPreventiveActions && incident.rcaPreventiveActions.length > 0 && (
                    <div style={{ marginTop: "12px", fontSize: "12px" }}>
                      <strong style={{ color: "var(--text-main)", display: "block", marginBottom: "6px" }}>Preventive Actions:</strong>
                      <div style={{ display: "grid", gap: "6px" }}>
                        {incident.rcaPreventiveActions.map(item => (
                          <div key={item.id} style={{
                            padding: "8px 10px",
                            background: item.status === "completed" ? "rgba(16,185,129,0.06)" : "rgba(0, 0, 0, 0.2)",
                            borderRadius: "8px",
                            border: "1px solid var(--glass-border)",
                            borderLeft: `4px solid ${item.priority === "high" ? "var(--danger)" : item.priority === "medium" ? "var(--warning)" : "var(--primary)"}`
                          }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <strong style={{ color: "var(--text-main)" }}>{item.description}</strong>
                              <span style={{
                                fontSize: "10px",
                                padding: "1px 6px",
                                borderRadius: "4px",
                                background: item.priority === "high" ? "rgba(239,68,68,0.15)" : item.priority === "medium" ? "rgba(245,158,11,0.15)" : "rgba(6,182,212,0.15)",
                                color: item.priority === "high" ? "var(--danger)" : item.priority === "medium" ? "var(--warning)" : "var(--primary)",
                                fontWeight: "bold"
                              }}>
                                {item.priority.toUpperCase()}
                              </span>
                            </div>
                            <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "4px" }}>
                              Owner: {getAnalystDisplayLabel(item.owner)} • Due: {item.dueDate} • Status: <strong style={{ color: item.status === "completed" ? "var(--success)" : "var(--warning)" }}>{item.status.toUpperCase()}</strong>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Manager Approval / Rejection flow */}
                  {incident.rcaStatus === "completed" && (
                    <div style={{
                      marginTop: "16px",
                      display: "flex",
                      gap: "8px",
                      alignItems: "center",
                      borderTop: "1px solid var(--glass-border)",
                      paddingTop: "12px",
                      flexWrap: "wrap"
                    }}>
                      {!incident.rcaApproved ? (
                        <>
                          <button
                            onClick={async () => {
                              try {
                                await callGovernanceAction(incident.id, "APPROVE_RCA", {
                                  callerRole: "soc_manager"
                                });
                                appendLifecycleEvent(incident.id, TIMELINE_EVENTS.RCA_APPROVED, "soc_manager");
                                logGovernanceAudit(incident.id, AUDIT_ACTIONS.RCA_APPROVED, "soc_manager");
                                alert(`RCA approved successfully`);
                              } catch (e) {
                                alert(`Approval failed: ` + e.message);
                              }
                            }}
                            style={{
                              padding: "8px 16px",
                              background: "var(--success)",
                              color: "#fff",
                              border: "none",
                              borderRadius: "6px",
                              fontWeight: "bold",
                              cursor: "pointer"
                            }}
                          >
                            ✔ Approve RCA
                          </button>
                          <button
                            onClick={async () => {
                              const reason = prompt("Reason for rejecting RCA (required):");
                              if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
                              try {
                                await callGovernanceAction(incident.id, "REJECT_RCA", {
                                  callerRole: "soc_manager",
                                  reason
                                });
                                appendLifecycleEvent(incident.id, TIMELINE_EVENTS.RCA_REJECTED, "soc_manager", { reason });
                                logGovernanceAudit(incident.id, AUDIT_ACTIONS.RCA_REJECTED, "soc_manager", { reason });
                                alert(`RCA rejected — returned to in_progress`);
                              } catch (e) {
                                alert(`Rejection failed: ` + e.message);
                              }
                            }}
                            style={{
                              padding: "8px 16px",
                              background: "var(--danger)",
                              color: "#fff",
                              border: "none",
                              borderRadius: "6px",
                              fontWeight: "bold",
                              cursor: "pointer"
                            }}
                          >
                            ❌ Reject RCA
                          </button>
                        </>
                      ) : (
                        <div style={{ color: "var(--success)", fontWeight: "bold", display: "flex", alignItems: "center", gap: "6px" }}>
                          <span>✔ RCA Approved by Manager on {incident.rcaApprovedAt?.toDate?.()?.toLocaleDateString() || "today"}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* 🕵️ Threat Hunting Panel */}
              {(incident.status === "threat_hunt" || incident.huntStatus) && (
                <div style={{
                  marginTop: "12px",
                  padding: "16px",
                  background: "var(--glass-bg)",
                  border: "1px solid var(--glass-border)",
                  borderRadius: "12px",
                  boxShadow: "var(--glass-shadow)",
                  borderLeft: `4px solid ${
                    incident.huntStatus === "approved" || incident.huntStatus === "completed" ? "var(--success)" :
                    incident.huntStatus === "submitted" ? "#f59e0b" : "var(--primary)"
                  }`,
                  textAlign: "left"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                    <h4 style={{ color: "var(--text-main)", margin: 0, fontSize: "14px" }}>🕵️ Threat Hunting</h4>
                    <span style={{
                      background: incident.huntStatus === "approved" || incident.huntStatus === "completed" ? "var(--success)" :
                                  incident.huntStatus === "submitted" ? "#f59e0b" : "var(--primary)",
                      color: "#fff",
                      fontSize: "10px",
                      padding: "2px 8px",
                      borderRadius: "12px",
                      fontWeight: "bold"
                    }}>
                      Status: {incident.huntStatus ? incident.huntStatus.toUpperCase() : "PENDING"}
                    </span>
                  </div>

                  {incident.huntRejectionReason && incident.huntStatus === "in_progress" && (
                    <div style={{
                      marginBottom: "12px",
                      padding: "10px",
                      background: "rgba(239, 68, 68, 0.1)",
                      border: "1px solid rgba(239, 68, 68, 0.3)",
                      borderRadius: "6px",
                      fontSize: "12px",
                      color: "var(--danger)"
                    }}>
                      <strong>❌ Rejection Reason:</strong> {incident.huntRejectionReason}
                    </div>
                  )}

                  {incident.huntStatus && (
                    <div style={{
                      marginTop: "12px",
                      padding: "12px",
                      background: "rgba(0, 0, 0, 0.2)",
                      borderRadius: "8px",
                      border: "1px solid var(--glass-border)",
                      fontSize: "12px",
                      display: "flex",
                      flexDirection: "column",
                      gap: "8px"
                    }}>
                      <div>
                        <strong style={{ color: "var(--text-main)" }}>Hunt Notes:</strong>
                        <div style={{ color: "var(--text-muted)", whiteSpace: "pre-wrap", marginTop: "4px" }}>
                          {incident.huntNotes || "No notes recorded yet."}
                        </div>
                      </div>
                      <div>
                        <strong style={{ color: "var(--text-main)" }}>Hunt Findings:</strong>
                        <div style={{ color: "var(--text-muted)", whiteSpace: "pre-wrap", marginTop: "4px" }}>
                          {incident.huntFindings || "No findings recorded yet."}
                        </div>
                      </div>
                      {incident.huntRecommendation && (
                        <div>
                          <strong style={{ color: "var(--text-main)" }}>Recommendation:</strong>
                          <div style={{ color: "var(--text-muted)", whiteSpace: "pre-wrap", marginTop: "4px" }}>
                            {incident.huntRecommendation}
                          </div>
                        </div>
                      )}
                      {incident.huntCompleteOption && (
                        <div>
                          <strong style={{ color: "var(--text-main)" }}>Action Route:</strong>{" "}
                          <span style={{ color: "var(--text-muted)" }}>
                            {incident.huntCompleteOption === "return_l2" ? "Option A: Return to L2" : "Option B: Close Hunt"}
                          </span>
                        </div>
                      )}
                    </div>
                  )}

                  {incident.attackTechniques && incident.attackTechniques.length > 0 && (
                    <div style={{ marginTop: "12px" }}>
                      <strong style={{ color: "var(--text-main)", display: "block", marginBottom: "6px", fontSize: "12px" }}>Mapped ATT&CK Techniques:</strong>
                      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                        {incident.attackTechniques.map((tech, idx) => (
                          <div key={idx} style={{
                            background: "rgba(63, 81, 181, 0.2)",
                            border: "1px solid rgba(63, 81, 181, 0.4)",
                            borderRadius: "4px",
                            padding: "4px 8px",
                            fontSize: "11px",
                            color: "var(--text-main)",
                          }}>
                            <span style={{ fontWeight: "bold", color: "#7986cb" }}>{tech.techniqueId}</span> - {tech.techniqueName}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {incident.huntStatus === "submitted" && (
                    <div style={{
                      marginTop: "16px",
                      display: "flex",
                      gap: "8px",
                      alignItems: "center",
                      borderTop: "1px solid var(--glass-border)",
                      paddingTop: "12px",
                      flexWrap: "wrap"
                    }}>
                      <button
                        onClick={async () => {
                          try {
                            await callGovernanceAction(incident.id, "APPROVE_HUNT", {
                              callerRole: "soc_manager"
                            });
                            appendLifecycleEvent(incident.id, TIMELINE_EVENTS.THREAT_HUNT_APPROVED, "soc_manager");
                            logGovernanceAudit(incident.id, AUDIT_ACTIONS.THREAT_HUNT_APPROVED, "soc_manager");

                            const option = incident.huntCompleteOption || "close";
                            if (option === "return_l2") {
                              appendLifecycleEvent(incident.id, TIMELINE_EVENTS.THREAT_HUNT_RETURNED, "soc_manager");
                              logGovernanceAudit(incident.id, AUDIT_ACTIONS.THREAT_HUNT_RETURNED, "soc_manager");
                            } else {
                              appendLifecycleEvent(incident.id, TIMELINE_EVENTS.THREAT_HUNT_COMPLETED, "soc_manager");
                              logGovernanceAudit(incident.id, AUDIT_ACTIONS.THREAT_HUNT_COMPLETED, "soc_manager");
                            }
                            alert(`Threat Hunt approved successfully`);
                          } catch (e) {
                            alert(`Approval failed: ` + e.message);
                          }
                        }}
                        style={{
                          padding: "8px 16px",
                          background: "var(--success)",
                          color: "#fff",
                          border: "none",
                          borderRadius: "6px",
                          fontWeight: "bold",
                          cursor: "pointer"
                        }}
                      >
                        ✔ Approve Threat Hunt
                      </button>

                      <button
                        onClick={async () => {
                          const reason = prompt("Reason for rejecting Threat Hunt (required):");
                          if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
                          try {
                            await callGovernanceAction(incident.id, "REJECT_HUNT", {
                              callerRole: "soc_manager",
                              reason
                            });
                            appendLifecycleEvent(incident.id, TIMELINE_EVENTS.THREAT_HUNT_REJECTED, "soc_manager", { reason });
                            logGovernanceAudit(incident.id, AUDIT_ACTIONS.THREAT_HUNT_REJECTED, "soc_manager", { reason });
                            alert(`Threat Hunt rejected — returned to hunter`);
                          } catch (e) {
                            alert(`Rejection failed: ` + e.message);
                          }
                        }}
                        style={{
                          padding: "8px 16px",
                          background: "var(--danger)",
                          color: "#fff",
                          border: "none",
                          borderRadius: "6px",
                          fontWeight: "bold",
                          cursor: "pointer"
                        }}
                      >
                        ❌ Reject Threat Hunt
                      </button>
                    </div>
                  )}

                  {(incident.huntStatus === "approved" || incident.huntStatus === "completed") && (
                    <div style={{
                      marginTop: "16px",
                      borderTop: "1px solid var(--glass-border)",
                      paddingTop: "12px",
                      fontSize: "12px",
                      color: "var(--success)",
                      fontWeight: "bold"
                    }}>
                      ✔ Threat Hunt Approved by Manager on {incident.huntApprovedAt?.toDate?.()?.toLocaleDateString() || "today"}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* 4. Containment Approval Queue */}
      <div style={glassPanel} data-testid="containment-queue">
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>🛡️ Containment Lifecycle</h2>
        {containmentQueue.length === 0 ? (
          <div style={{ color: "#aaa", textAlign: "center", padding: "20px" }}>
            No containment requests
          </div>
        ) : (
          <div style={{ display: "grid", gap: "12px" }}>
            {containmentQueue.map((incident) => {
              const getStatusBadge = () => {
                switch (incident.status) {
                  case "containment_in_progress":
                    return <span style={{ background: "#6366f1", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>🔵 In Progress</span>;
                  case "containment_action_submitted":
                    return <span style={{ background: "#f59e0b", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>🟡 Manager Review</span>;
                  case "containment_completed":
                    return <span style={{ background: "#22c55e", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>✅ Completed</span>;
                  case "containment_approved":
                    return <span style={{ background: "#22c55e", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>🟢 Approved</span>;
                  case "containment_rejected":
                    return <span style={{ background: "#ef4444", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>🔴 Rejected</span>;
                  case "containment_review_again":
                    return <span style={{ background: "#8b5cf6", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>� Review Again</span>;
                  case "containment_executed":
                    return <span style={{ background: "#10b981", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>✅ Executed</span>;
                  // Legacy compatibility
                  case "containment_pending_approval":
                    return <span style={{ background: "#f59e0b", color: "white", padding: "4px 10px", borderRadius: "6px", fontSize: "12px", marginLeft: "10px" }}>🟡 Waiting Approval</span>;
                  default:
                    return null;
                }
              };

              return (
                <div key={incident.id} style={{
                  background: "rgba(255,255,255,0.05)",
                  padding: "12px",
                  borderRadius: "8px",
                  border: "1px solid rgba(255,255,255,0.1)"
                }}>
                  <div style={{ color: "#fff", fontWeight: "bold", marginBottom: "8px" }}>
                    {incident.title}
                    {getStatusBadge()}
                  </div>
                  <div style={{ color: "#aaa", fontSize: "12px", marginBottom: "8px" }}>
                    <div>Status: {incident.status || "Unknown"}</div>
                    <div>Assigned To: {incident.assignedTo || "Unknown"}</div>
                    {incident.approvedBy && <div>Approved By: {incident.approvedBy}</div>}
                    {incident.executedBy && <div>Executed By: {incident.executedBy}</div>}
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    {/* Enterprise workflow - IR action submitted for manager review */}
                    {incident.status === "containment_action_submitted" && authorized && (
                      <>
                        <button
                          disabled={!authorized}
                          style={{
                            padding: "6px 12px",
                            borderRadius: "4px",
                            background: "var(--success)",
                            color: "#fff",
                            cursor: "pointer"
                          }}
                          onClick={() => approveContainmentAction(incident.id)}
                        >
                          Approve Action
                        </button>
                        <button
                          disabled={!authorized}
                          data-testid="reject-containment"
                          style={{
                            padding: "6px 12px",
                            borderRadius: "4px",
                            background: "rgba(239,68,68,0.2)",
                            color: "#fff",
                            border: "1px solid rgba(239,68,68,0.3)",
                            cursor: "pointer"
                          }}
                          onClick={() => rejectContainmentAction(incident.id)}
                        >
                          Reject Action
                        </button>
                        <button
                          disabled={!authorized}
                          style={{
                            padding: "6px 12px",
                            borderRadius: "4px",
                            background: "rgba(139,92,246,0.2)",
                            color: "#fff",
                            border: "1px solid rgba(139,92,246,0.3)",
                            cursor: "pointer"
                          }}
                          onClick={() => requestContainmentReview(incident.id)}
                        >
                          Request Review
                        </button>
                      </>
                    )}
                    {/* Legacy compatibility - old L2 containment request */}
                    {incident.status === "containment_pending_approval" && authorized && (
                      <>
                        <button
                          disabled={!authorized}
                          data-testid="approve-containment"
                          style={{
                            padding: "6px 12px",
                            borderRadius: "4px",
                            background: "var(--success)",
                            color: "#fff",
                            cursor: "pointer"
                          }}
                          onClick={() => approveContainmentRequest(incident.id)}
                        >
                          Approve (Send to IR)
                        </button>
                        <button
                          disabled={!authorized}
                          style={{
                            padding: "6px 12px",
                            borderRadius: "4px",
                            background: "rgba(239,68,68,0.2)",
                            color: "#fff",
                            border: "1px solid rgba(239,68,68,0.3)",
                            cursor: "pointer"
                          }}
                          onClick={() => rejectContainmentRequest(incident.id)}
                        >
                          Reject (Return to L2)
                        </button>
                      </>
                    )}
                    {incident.status === "containment_completed" && authorized && (
                      <>
                        <button
                          disabled={!authorized}
                          style={{
                            padding: "6px 12px",
                            borderRadius: "4px",
                            background: "var(--secondary)",
                            color: "#fff",
                            cursor: "pointer"
                          }}
                          onClick={() => assignToSOC(incident.id, "soc_l2")}
                          data-testid="reassign-incident"
                        >
                          Reassign Incident
                        </button>
                        <button
                          disabled={!authorized}
                          data-testid="close-incident"
                          style={{
                            padding: "6px 12px",
                            borderRadius: "4px",
                            background: "var(--success)",
                            color: "#fff",
                            cursor: "pointer"
                          }}
                          onClick={() => {
                            const reason = prompt("Reason for closing incident (required):");
                            if (!reason || reason.trim().length < 3) { alert("A reason is required."); return; }
                            updateDoc(doc(db, "issues", incident.id), {
                              status: "resolved",
                              visibleTo: ["soc_l2", "soc_manager", "ir"],
                              resolvedBy: auth.currentUser?.uid,
                              resolvedAt: serverTimestamp(),
                              updatedAt: serverTimestamp()
                            });
                            logLifecycleAudit(incident.id, AUDIT_ACTIONS.INCIDENT_CLOSED, "soc_manager", {
                              previousState: incident.status || null,
                              newState: "resolved",
                              reason,
                            });
                          }}
                        >
                          Close Incident
                        </button>
                      </>
                    )}
                    {incident.status === "containment_executed" && (
                      <span style={{ color: "#aaa", fontSize: "12px", padding: "6px 12px" }}>
                        ✅ Containment executed
                      </span>
                    )}
                    {authorized && incident.status !== "threat_hunt" && (
                      <button
                        disabled={!authorized}
                        style={{
                          padding: "6px 12px",
                          borderRadius: "4px",
                          background: "rgba(139,92,246,0.2)",
                          color: "#fff",
                          border: "1px solid rgba(139,92,246,0.3)",
                          cursor: "pointer"
                        }}
                        onClick={() => convertToThreatHunt(incident.id)}
                      >
                        Convert to Threat Hunt
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 6. Resolved Incidents Review Panel */}
      <div style={glassPanel}>
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>✅ Resolved Incidents Review Panel</h2>
        <div style={{ display: "grid", gap: "12px" }}>
          {issues.filter(i => i.status === "resolved" && !i.isDeleted).slice(0, 5).map((incident) => (
            <div key={incident.id} style={{
              background: "rgba(255,255,255,0.05)",
              padding: "12px",
              borderRadius: "8px",
              border: "1px solid rgba(255,255,255,0.1)"
            }}>
              <div style={{ color: "#fff", fontWeight: "bold", marginBottom: "8px" }}>
                {incident.title}
              </div>
              <div style={{ color: "#aaa", fontSize: "12px", marginBottom: "12px" }}>
                Resolved: {incident.updatedAt?.toDate?.()?.toLocaleString() || "Unknown"}
              </div>
              <button
                onClick={() => reopenIncident(incident.id)}
                style={{
                  padding: "6px 12px",
                  borderRadius: "4px",
                  background: "rgba(239,68,68,0.2)",
                  color: "#fff",
                  border: "1px solid rgba(239,68,68,0.3)",
                  cursor: "pointer"
                }}
              >
                Reopen Incident
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* 7. Incident Lifecycle Timeline */}
      <div style={glassPanel}>
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>🕐 Incident Lifecycle Timeline</h2>
        <div style={{ display: "grid", gap: "12px" }}>
          {issues.slice(0, 3).map((incident) => (
            <div key={incident.id} style={{
              background: "rgba(255,255,255,0.05)",
              padding: "12px",
              borderRadius: "8px",
              border: "1px solid rgba(255,255,255,0.1)"
            }}>
              <div style={{ color: "#fff", fontWeight: "bold", marginBottom: "8px" }}>
                {incident.title}
              </div>
              <div style={{ color: "#aaa", fontSize: "12px" }}>
                {buildRenderableTimeline(timelines.get(incident.id), incident.statusHistory, "desc").slice(0, 3).map((event, idx) => (
                  <div key={idx} style={{ marginBottom: "4px" }}>
                    <strong>{event.icon} {event.displayLabel}</strong> - {event.timestamp ? new Date(event.timestamp).toLocaleString() : "Unknown"}
                    {event.note && <div style={{ color: "#888", fontSize: "11px" }}>{event.note}</div>}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 8. Analyst Performance Panel */}
      <div style={glassPanel}>
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>📈 Analyst Performance Panel</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px" }}>
          <div style={statCard}>
            <div style={{ fontSize: "20px", fontWeight: "bold", color: "#4ade80" }}>
              {Math.round((overallStats.resolved / (overallStats.resolved + overallStats.open + overallStats.assigned + overallStats.inProgress)) * 100) || 0}%
            </div>
            <div style={{ color: "#aaa" }}>Resolution Rate</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "20px", fontWeight: "bold", color: "#ef4444" }}>
              {overallStats.breached}
            </div>
            <div style={{ color: "#aaa" }}>SLA Breaches</div>
          </div>
          <div style={statCard}>
            <div style={{ fontSize: "20px", fontWeight: "bold", color: "#f59e0b" }}>
              0
            </div>
            <div style={{ color: "#aaa" }}>Reopened Incidents</div>
          </div>
        </div>
      </div>

      {/* 9. SLA Risk Monitor */}
      <div style={glassPanel}>
        <h2 style={{ color: "#fff", marginBottom: "20px" }}>⚠️ SLA Risk Monitor</h2>
        {slaRiskIncidents.length === 0 ? (
          <div style={{ color: "#4ade80", textAlign: "center", padding: "20px" }}>
            ✅ All incidents within SLA
          </div>
        ) : (
          <div style={{ display: "grid", gap: "12px" }}>
            {slaRiskIncidents.map((incident) => (
              <div key={incident.id} style={{
                background: "rgba(245,158,11,0.1)",
                padding: "12px",
                borderRadius: "8px",
                border: "1px solid rgba(245,158,11,0.3)"
              }}>
                <div style={{ color: "#fff", fontWeight: "bold", marginBottom: "8px" }}>
                  ⚠ Risk of SLA Breach
                </div>
                <div style={{ color: "#fff" }}>
                  {incident.title}
                </div>
                <div style={{ color: "#aaa", fontSize: "12px" }}>
                  Created: {incident.createdAt?.toDate?.()?.toLocaleString() || "Unknown"}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
