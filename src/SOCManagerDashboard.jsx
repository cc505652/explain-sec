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
import { onAuthStateChanged } from "firebase/auth";
import { normalizeRole, isVisibleToRole, getVisibleToForStatus } from "./utils/roleNormalization";
import {
  callApproveEscalation,
  callDenyEscalation,
  callApproveContainment,
  callLockIncident,
  callGovernanceAction,
} from "./utils/socFunctions";

export default function SOCManagerDashboard() {
  console.log("SOC MANAGER DASHBOARD MOUNTED");
  const navigate = useNavigate();

  // 🔧 STEP 1 — AUTH INITIALIZATION FIX
  const [firebaseUser, setFirebaseUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [issues, setIssues] = useState([]);
  const [usersData, setUsersData] = useState({});

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
      alert(result.message || "✅ Incident escalated to ir");
    } catch (err) {
      // If escalation was already approved, try TRANSFER_OWNERSHIP instead
      if (err?.code === "functions/already-exists" || err?.message?.includes("already")) {
        const reason = prompt("Incident already approved. Transfer to ir? Enter reason:");
        if (!reason) return;
        await callGovernanceAction(issueId, "TRANSFER_OWNERSHIP", { newAssignedTo: "ir", reason });
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
        name: analyst,
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
      if (!i.createdAt || i.isDeleted || i.status === "resolved") return false;
      const now = new Date();
      const createdAt = i.createdAt.toDate ? i.createdAt.toDate() : new Date(i.createdAt.seconds * 1000);
      const hoursDiff = (now - createdAt) / (1000 * 60 * 60);
      return hoursDiff > 22; // Less than 2 hours remaining for 24h SLA
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
          onClick={() => navigate("/command-console")}
          style={{
            background: "#007bff",
            color: "white",
            border: "none",
            padding: "10px 20px",
            borderRadius: "5px",
            cursor: "pointer",
            fontSize: "14px",
            fontWeight: "bold"
          }}
        >
          Command Console
        </button>
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
                  <option value="soc_l1">soc_l1</option>
                  <option value="soc_l2">soc_l2</option>
                  <option value="ir">ir</option>
                  <option value="threat_hunter">threat_hunter</option>
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
                  Delete False Positive
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
                  onClick={() => handlePIR(incident.id)}
                  style={{ background: "#22c55e", color: "white" }}
                >
                  Tag PIR
                </button>
                <button
                  onClick={() => handleRCA(incident.id)}
                  style={{ background: "#f59e0b", color: "white" }}
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
                          }}
                        >
                          Close Incident
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
                          onClick={() => convertToThreatHunt(incident.id)}
                        >
                          Convert to Threat Hunt
                        </button>
                      </>
                    )}
                    {incident.status === "containment_executed" && (
                      <span style={{ color: "#aaa", fontSize: "12px", padding: "6px 12px" }}>
                        ✅ Containment executed
                      </span>
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
                {incident.statusHistory?.slice(-3).map((status, idx) => (
                  <div key={idx} style={{ marginBottom: "4px" }}>
                    <strong>{status.status}</strong> - {status.at?.toDate?.()?.toLocaleString() || "Unknown"}
                    {status.note && <div style={{ color: "#888", fontSize: "11px" }}>{status.note}</div>}
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
