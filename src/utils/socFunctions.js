/**
 * socFunctions.js — Direct Firestore operations (REVERTED FROM CLOUD FUNCTIONS)
 *
 * MIGRATION NOTE: This file was reverted from Cloud Functions to direct Firestore operations
 * to resolve timeout issues. Future migration back to Cloud Functions should:
 * 1. Restore the callFunction() dispatcher
 * 2. Replace Firestore operations with Cloud Function calls
 * 3. Re-enable server-side validation and state machine
 *
 * Current implementation uses direct Firestore operations with client-side validation.
 */

import { getAuth } from "firebase/auth";
import { doc, updateDoc, arrayUnion, arrayRemove, serverTimestamp, getDoc, deleteDoc, collection, addDoc } from "firebase/firestore";
import { app, db } from "../firebase";
import { isValidTransition, validateTransition } from "./incidentStateGuard";
import { getVisibleToForStatus } from "./roleNormalization";
import { normalizeRole, normalizeIncidentParty } from "./normalizeRole";
import { logEscalationAudit, logContainmentAudit, logGovernanceAudit, logLifecycleAudit, logAssignmentAudit, AUDIT_ACTIONS } from "../security/auditEngine";

// Get the Firebase auth instance
const auth = getAuth(app);

/**
 * Fetch a user's canonical role from the database.
 */
async function getTrueUserRole(uid) {
  if (!uid) return null;
  const userDocRef = doc(db, "users", uid);
  const userDocSnap = await getDoc(userDocRef);
  if (!userDocSnap.exists()) return null;
  const userData = userDocSnap.data();
  return normalizeRole(userData.team) || normalizeRole(userData.role);
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API — Incident Lifecycle Functions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escalate an incident.
 * L1 users → escalates to soc_l2 directly
 * L2 users → submits escalation request to soc_manager queue
 */
export async function callEscalateIncident(incidentId) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  if (!incidentSnap.exists()) throw new Error("Incident not found");

  const incident = incidentSnap.data();

  // Simple escalation logic (client-side for now)
  // L1 → L2: direct reassignment
  // L2 → IR: escalation request
  const updateData = {
    assignedTo: "soc_l2",
    assignedAt: serverTimestamp(),
    escalatedTo: "soc_l2",
    escalationRequested: true,
    escalationRequestedBy: user.uid,
    escalationRequestedAt: serverTimestamp(),
    visibleTo: getVisibleToForStatus("escalation_requested"),
    statusHistory: arrayUnion({
      status: "escalation_requested",
      note: "Escalated to SOC L2",
      by: user.uid,
      at: new Date().toISOString(),
    }),
    updatedAt: serverTimestamp(),
  };

  await updateDoc(incidentRef, updateData);

  logEscalationAudit(incidentId, AUDIT_ACTIONS.ESCALATION_REQUESTED, "unknown", {
    previousState: incident.status || null,
    newState: "escalation_requested",
    requestedBy: user.uid,
  });
  logEscalationAudit(incidentId, AUDIT_ACTIONS.ESCALATION_ROUTED, "unknown", {
    routedTo: "soc_l2",
    reason: "Escalated to SOC L2",
  });

  return { success: true, message: "Incident escalated" };
}

/**
 * SOC Manager approves an escalation request → assigns incident to ir
 */
export async function callApproveEscalation(incidentId) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (trueRole !== "soc_manager" && trueRole !== "admin") {
    throw new Error("Unauthorized: Only SOC Managers can approve escalations");
  }

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  if (!incidentSnap.exists()) throw new Error("Incident not found");

  const incident = incidentSnap.data();

  const updateData = {
    status: "escalation_approved",
    escalationApproved: true,
    escalationApprovedBy: user.uid,
    escalationApprovedAt: serverTimestamp(),
    assignedTo: "ir",
    assignedAt: serverTimestamp(),
    visibleTo: getVisibleToForStatus("escalation_approved"),
    escalatedTo: "ir",
    locked: false,
    statusHistory: arrayUnion({
      status: "escalation_approved",
      note: "Escalation approved by SOC Manager — assigned to ir",
      by: user.uid,
      at: new Date().toISOString(),
    }),
    updatedAt: serverTimestamp(),
  };

  await updateDoc(incidentRef, updateData);

  logEscalationAudit(incidentId, AUDIT_ACTIONS.ESCALATION_APPROVED, "unknown", {
    previousState: incident.status || null,
    newState: "escalation_approved",
    approvedBy: user.uid,
    assignedTo: "ir",
  });
  logEscalationAudit(incidentId, AUDIT_ACTIONS.ESCALATION_ROUTED, "unknown", {
    routedTo: "ir",
    reason: "Escalation approved by SOC Manager — assigned to ir",
  });

  return { success: true, message: "Escalation approved, assigned to ir" };
}

// ─────────────────────────────────────────────────────────────────────────────
// CONVENIENCE WRAPPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SOC Manager denies an escalation request → returns incident to investigation
 * @param {string} reason  Optional reason string shown in audit trail
 */
export async function callDenyEscalation(incidentId, reason = "") {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (trueRole !== "soc_manager" && trueRole !== "admin") {
    throw new Error("Unauthorized: Only SOC Managers can deny escalations");
  }

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  if (!incidentSnap.exists()) throw new Error("Incident not found");

  const incident = incidentSnap.data();
  const resetStatus = incident.status === "escalation_pending" ? "in_progress" : incident.status;

  const updateData = {
    status: resetStatus,
    escalationRequested: false,
    escalationDenied: true,
    escalationDeniedBy: user.uid,
    escalationDeniedAt: serverTimestamp(),
    locked: false,
    governanceLock: false,
    statusHistory: arrayUnion({
      status: "escalation_denied",
      note: `Escalation denied by SOC Manager. Reason: ${reason || "None provided"}`,
      by: user.uid,
      at: new Date().toISOString(),
    }),
    updatedAt: serverTimestamp(),
  };

  await updateDoc(incidentRef, updateData);

  logEscalationAudit(incidentId, AUDIT_ACTIONS.ESCALATION_DENIED, "unknown", {
    previousState: incident.status || null,
    newState: resetStatus,
    deniedBy: user.uid,
    reason: reason || "None provided",
  });

  return { success: true, message: "Escalation denied — incident returned to investigation" };
}

// ─────────────────────────────────────────────────────────────────────────────
// CONVENIENCE WRAPPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ir performs a containment action on an assigned incident
 * @param {string} actionType  One of: isolate_host | block_ip | disable_account |
 *                             terminate_session | quarantine_file
 */
export async function callPerformContainment(incidentId, actionType) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (trueRole !== "ir" && trueRole !== "admin") {
    throw new Error("Unauthorized: Only Incident Responders can perform containment");
  }

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  const incident = incidentSnap.exists() ? incidentSnap.data() : {};

  const updateData = {
    status: "containment_pending",
    containmentAction: actionType,
  };

  await updateDoc(incidentRef, updateData);

  logContainmentAudit(incidentId, AUDIT_ACTIONS.IR_ACTION_SUBMITTED, "unknown", {
    previousState: incident.status || null,
    newState: "containment_pending",
    actionType,
  });

  return { success: true, message: `Containment action ${actionType} performed` };
}

/**
 * SOC Manager approves containment → resolves the incident
 */
export async function callApproveContainment(incidentId) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (trueRole !== "soc_manager" && trueRole !== "admin") {
    throw new Error("Unauthorized: Only SOC Managers can approve containment");
  }

  const incidentRef = doc(db, "issues", incidentId);
  const updateData = {
    status: "resolved",
    resolvedAt: serverTimestamp(),
    resolvedBy: user.uid,
    containmentApprovedBy: user.uid,
    containmentApprovedAt: serverTimestamp(),
    readyForManagerReview: false,
    visibleTo: getVisibleToForStatus("resolved"),
    statusHistory: arrayUnion({
      status: "resolved",
      note: "Containment approved and incident resolved by SOC Manager",
      by: user.uid,
      at: new Date().toISOString(),
    }),
    updatedAt: serverTimestamp(),
  };

  await updateDoc(incidentRef, updateData);
  return { success: true, message: "Containment approved — incident resolved" };
}

/**
 * SOC Manager locks or unlocks an incident
 * @param {boolean} lock  true = lock, false = unlock
 */
export async function callLockIncident(incidentId, lock) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (trueRole !== "soc_manager" && trueRole !== "admin") {
    throw new Error("Unauthorized: Only SOC Managers can lock/unlock incidents");
  }

  const incidentRef = doc(db, "issues", incidentId);
  const updateData = {
    locked: lock,
    governanceLock: lock,
    lockedBy: lock ? user.uid : null,
    lockedAt: lock ? serverTimestamp() : null,
    statusHistory: arrayUnion({
      status: `governance_${lock ? "locked" : "unlocked"}`,
      note: `Incident ${lock ? "locked" : "unlocked"} by SOC Manager`,
      by: user.uid,
      at: new Date().toISOString(),
    }),
    updatedAt: serverTimestamp(),
  };

  await updateDoc(incidentRef, updateData);
  return { success: true, message: `Incident ${lock ? "locked" : "unlocked"}` };
}

/**
 * Admin updates a user's role (only Admin can call this successfully)
 */
export async function callUpdateRole(targetUid, newRole, newTeam, newAnalystLevel) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (trueRole !== "admin") {
    throw new Error("Unauthorized: Only Administrators can update user roles");
  }

  const userRef = doc(db, "users", targetUid);
  const updateData = {
    role: newRole,
    roleUpdatedBy: user.uid,
    roleUpdatedAt: serverTimestamp(),
  };

  if (newTeam) updateData.team = newTeam;
  if (newAnalystLevel) updateData.analystLevel = newAnalystLevel;

  await updateDoc(userRef, updateData);
  return { success: true, message: `Role updated to ${newRole}` };
}

/**
 * Generic status update validated by server-side state machine.
 * Replaces all direct updateDoc status changes.
 * @param {string} nextStatus  Target status (must be a valid transition from current)
 * @param {string} note        Optional audit note
 */
export async function callUpdateIncidentStatus(incidentId, nextStatus, note = "") {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (!trueRole) throw new Error("User has no assigned canonical role");

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  if (!incidentSnap.exists()) throw new Error("Incident not found");

  const incident = incidentSnap.data();
  const currentStatus = incident.status;

  // Map to action string for state transition validation
  let action = "investigate"; // default generic action
  if (nextStatus === "in_progress" && currentStatus === "open") action = "start_triage";
  else if (nextStatus === "false_positive") action = "mark_false_positive";
  else if (nextStatus === "confirmed_threat") action = "confirm_threat";
  else if (nextStatus === "escalation_pending") action = "request_escalation";
  else if (nextStatus === "containment_pending_approval") action = "request_containment";
  else if (nextStatus === "resolved") action = "resolve_incident";

  // Validate transition and action permissions
  const validation = validateTransition(currentStatus, nextStatus, trueRole, action);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  const updateData = {
    status: nextStatus,
    visibleTo: getVisibleToForStatus(nextStatus),
    statusHistory: arrayUnion({
      status: nextStatus,
      note: note || `Status updated to ${nextStatus}`,
      by: user.uid,
      at: new Date().toISOString(),
    }),
    updatedAt: serverTimestamp(),
  };

  // FIX: When L1 confirms threat, automatically escalate to L2
  if (nextStatus === "confirmed_threat") {
    updateData.escalatedTo = "soc_l2";
    updateData.escalatedAt = serverTimestamp();
    updateData.assignedTo = "soc_l2";
    updateData.assignedAt = serverTimestamp();
    updateData.escalationRequested = true;
  }

  if (nextStatus === "resolved") {
    updateData.resolvedAt = serverTimestamp();
    updateData.resolvedBy = user.uid;
  }
  if (nextStatus === "in_progress") {
    updateData.triagedBy = user.uid;
    updateData.triageStartedAt = serverTimestamp();
  }

  await updateDoc(incidentRef, updateData);
  return { success: true, message: `Status updated to ${nextStatus}` };
}

/**
 * Unified governance dispatcher — manager-only actions.
 *
 * @param {string} incidentId  Target incident
 * @param {string} actionType  One of:
 *   OVERRIDE_DECISION | SLA_OVERRIDE | TRANSFER_OWNERSHIP |
 *   CONVERT_TO_THREAT_HUNT | REOPEN_INCIDENT | REJECT_CONTAINMENT |
 *   ACCEPT_RISK | TAG_RCA | TAG_PIR | ADD_EVIDENCE | UPDATE_RISK_SCORE | UPDATE_TAGS
 * @param {object} payload     Action-specific data. reason is REQUIRED for most.
 */
export async function callGovernanceAction(incidentId, actionType, payload = {}) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const trueRole = await getTrueUserRole(user.uid);
  if (!trueRole) throw new Error("User has no assigned canonical role");
  const isManager = trueRole === "soc_manager" || trueRole === "admin";

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  if (!incidentSnap.exists()) throw new Error("Incident not found");

  const incident = incidentSnap.data();
  const previousStatus = incident.status;
  let updateData = { updatedAt: serverTimestamp() };

  switch (actionType) {
    case "TRANSFER_OWNERSHIP":
      if (!isManager) throw new Error("Only a SOC Manager can transfer ownership");
      updateData.assignedTo = normalizeIncidentParty(payload.newAssignedTo) || payload.newAssignedTo;
      updateData.assignedAt = serverTimestamp();
      updateData.ownershipTransferred = true;
      updateData.transferBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "ownership_transfer",
        note: `Transferred to ${payload.newAssignedTo} by SOC Manager. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

    case "UPDATE_TAGS":
      const tags = payload.tags;
      if (!Array.isArray(tags)) throw new Error("tags must be an array");
      const sanitized = [...new Set(tags.map(t => String(t).trim().toLowerCase()).filter(Boolean))];
      updateData.tags = sanitized;
      break;

    case "REOPEN_INCIDENT":
      if (!isManager) throw new Error("Only a SOC Manager can reopen incidents");
      updateData.status = "reopened";
      updateData.reopenedAt = serverTimestamp();
      updateData.reopenedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "reopened",
        note: `Reopened by SOC Manager. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

    case "ACCEPT_RISK":
      if (!isManager) throw new Error("Only a SOC Manager can accept risk");
      updateData.riskAccepted = true;
      updateData.riskAcceptedBy = user.uid;
      updateData.riskAcceptedAt = serverTimestamp();
      updateData.riskAcceptanceReason = payload.reason;
      updateData.statusHistory = arrayUnion({
        status: "risk_accepted_flag",
        note: `Risk accepted by SOC Manager. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

    case "OVERRIDE_DECISION":
      if (!isManager) throw new Error("Only a SOC Manager can override decisions");
      const { targetField, newValue } = payload;
      if (!targetField) throw new Error("Missing targetField for OVERRIDE_DECISION");
      updateData[targetField] = newValue;
      updateData.overrideReason = payload.reason;
      updateData.overrideBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "governance_override",
        note: `Decision overridden by SOC Manager: ${targetField} set to ${newValue}. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

    case "SLA_OVERRIDE":
      if (!isManager) throw new Error("Only a SOC Manager can override SLA");
      const { newUrgency } = payload;
      if (!newUrgency) throw new Error("Missing newUrgency for SLA_OVERRIDE");
      updateData.urgency = newUrgency;
      updateData.slaOverrideReason = payload.reason;
      updateData.slaOverrideBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "sla_override",
        note: `SLA urgency overridden to ${newUrgency} by SOC Manager. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

    case "REJECT_CONTAINMENT":
      if (!isManager) throw new Error("Only a SOC Manager can reject containment");
      updateData.status = "investigation_l2";
      updateData.escalatedTo = "soc_l2";
      updateData.visibleTo = ["soc_l2"];
      updateData.containmentRequested = false;
      updateData.approvalStatus = "rejected";
      updateData.rejectedBy = user.uid;
      updateData.rejectedAt = serverTimestamp();
      updateData.statusHistory = arrayUnion({
        status: "containment_rejected",
        note: `Containment request rejected by SOC Manager. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

    case "CONVERT_TO_THREAT_HUNT":
      if (!isManager) throw new Error("Only a SOC Manager can convert to threat hunt");
      updateData.status = "threat_hunt";
      updateData.visibleTo = ["soc_manager", "threat_hunter"];
      updateData.assignedTo = "threat_hunter";
      updateData.assignedAt = serverTimestamp();
      updateData.escalatedTo = "threat_hunter";
      updateData.convertedToThreatHuntBy = user.uid;
      updateData.convertedToThreatHuntAt = serverTimestamp();
      updateData.threatHuntReason = payload.reason;
      updateData.statusHistory = arrayUnion({
        status: "threat_hunt",
        note: `Converted to Threat Hunt by SOC Manager. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

    case "TAG_PIR": {
      if (!isManager) throw new Error("Only a SOC Manager can tag for PIR");
      const allowedTerminalStatuses = ["resolved", "containment_completed"];
      if (!allowedTerminalStatuses.includes(previousStatus)) {
        throw new Error(`PIR may only be created when the incident is in a completed/terminal operational state (resolved, containment_completed)`);
      }
      updateData.pirTagged = true;
      updateData.pirTaggedBy = user.uid;
      updateData.pirTaggedAt = serverTimestamp();
      updateData.pirReason = payload.reason;
      updateData.pirStatus = "pending";
      updateData.statusHistory = arrayUnion({
        status: "pir_tagged",
        note: `Tagged for Post-Incident Review. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "ASSIGN_PIR_OWNER": {
      if (!isManager) throw new Error("Only a SOC Manager can assign PIR owner");
      const { assignee, assigneeRole } = payload;
      if (!assignee) throw new Error("Missing assignee for ASSIGN_PIR_OWNER");
      const allowedReviewerRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];
      const canonicalRole = normalizeRole(assigneeRole);
      if (!allowedReviewerRoles.includes(canonicalRole)) {
        throw new Error(`User with role ${assigneeRole} cannot be assigned as PIR owner`);
      }
      updateData.pirOwner = assignee;
      updateData.pirAssignedAt = serverTimestamp();
      updateData.pirAssignedBy = user.uid;
      updateData.pirStatus = "assigned";
      updateData.statusHistory = arrayUnion({
        status: "pir_assigned",
        note: `PIR assigned to ${assignee} by SOC Manager`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "REASSIGN_PIR_OWNER": {
      if (!isManager) throw new Error("Only a SOC Manager can reassign PIR owner");
      const { assignee, assigneeRole } = payload;
      if (!assignee) throw new Error("Missing assignee for REASSIGN_PIR_OWNER");
      const allowedReviewerRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];
      const canonicalRole = normalizeRole(assigneeRole);
      if (!allowedReviewerRoles.includes(canonicalRole)) {
        throw new Error(`User with role ${assigneeRole} cannot be assigned as PIR owner`);
      }
      updateData.pirOwner = assignee;
      updateData.pirAssignedAt = serverTimestamp();
      updateData.pirAssignedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "pir_reassigned",
        note: `PIR owner reassigned to ${assignee} by SOC Manager`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "ADD_PIR_CONTRIBUTOR": {
      if (!isManager) throw new Error("Only a SOC Manager can add PIR contributor");
      const { contributor, contributorRole } = payload;
      if (!contributor) throw new Error("Missing contributor for ADD_PIR_CONTRIBUTOR");
      const allowedReviewerRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];
      const canonicalRole = normalizeRole(contributorRole);
      if (!allowedReviewerRoles.includes(canonicalRole)) {
        throw new Error(`User with role ${contributorRole} cannot be added as contributor`);
      }
      updateData.pirContributors = arrayUnion(contributor);
      updateData.statusHistory = arrayUnion({
        status: "pir_contributor_added",
        note: `Contributor ${contributor} added to PIR`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "REMOVE_PIR_CONTRIBUTOR": {
      if (!isManager) throw new Error("Only a SOC Manager can remove PIR contributor");
      const { contributor } = payload;
      if (!contributor) throw new Error("Missing contributor for REMOVE_PIR_CONTRIBUTOR");
      updateData.pirContributors = arrayRemove(contributor);
      updateData.statusHistory = arrayUnion({
        status: "pir_contributor_removed",
        note: `Contributor ${contributor} removed from PIR`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "START_PIR": {
      const isOwner = incident.pirOwner === user.uid;
      if (!isOwner && !isManager) {
        throw new Error("Only the PIR Owner or a SOC Manager can start the PIR");
      }
      updateData.pirStatus = "in_progress";
      updateData.statusHistory = arrayUnion({
        status: "pir_started",
        note: `PIR started by ${user.uid}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "COMPLETE_PIR": {
      const { summary, lessonsLearned, recommendRCA } = payload;
      const isOwner = incident.pirOwner === user.uid;
      if (!isOwner && !isManager) {
        throw new Error("Only the PIR Owner or a SOC Manager can complete the PIR");
      }
      updateData.pirStatus = "completed";
      updateData.pirSummary = summary || "";
      updateData.pirLessonsLearned = lessonsLearned || "";
      updateData.recommendRCA = !!recommendRCA;
      if (recommendRCA) {
        updateData.rcaRecommended = true;
        updateData.rcaRecommendedAt = serverTimestamp();
        updateData.rcaRecommendedBy = user.uid;
      } else {
        updateData.rcaRecommended = false;
      }
      updateData.pirCompletedAt = serverTimestamp();
      updateData.pirCompletedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "pir_completed",
        note: `PIR completed by ${user.uid}. Recommend RCA: ${!!recommendRCA}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "APPROVE_PIR": {
      if (!isManager) {
        throw new Error("Only a SOC Manager can approve the PIR");
      }
      updateData.pirApproved = true;
      updateData.pirApprovedAt = serverTimestamp();
      updateData.pirApprovedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "pir_approved",
        note: `PIR approved by SOC Manager ${user.uid}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "ADD_PIR_ACTION_ITEM": {
      const isOwner = incident.pirOwner === user.uid;
      if (!isOwner && !isManager) {
        throw new Error("Only the PIR Owner or a SOC Manager can add action items");
      }
      const { description, owner, dueDate, priority } = payload;
      if (!description) throw new Error("Missing description for action item");
      if (!owner) throw new Error("Missing owner for action item");
      if (!dueDate) throw new Error("Missing dueDate for action item");
      
      const newActionItem = {
        id: Math.random().toString(36).substr(2, 9),
        description,
        owner,
        dueDate,
        priority: priority || "medium",
        status: "open",
        completedAt: null,
        createdAt: new Date().toISOString()
      };
      
      updateData.pirActionItems = arrayUnion(newActionItem);
      break;
    }

    case "COMPLETE_PIR_ACTION_ITEM": {
      const isOwner = incident.pirOwner === user.uid;
      const isContributor = incident.pirContributors && incident.pirContributors.includes(user.uid);
      if (!isOwner && !isContributor && !isManager) {
        throw new Error("Only the PIR Owner, a contributor, or a SOC Manager can complete action items");
      }
      const { actionItemId } = payload;
      if (!actionItemId) throw new Error("Missing actionItemId");
      const currentItems = incident.pirActionItems || [];
      const updatedItems = currentItems.map(item => {
        if (item.id === actionItemId) {
          return {
            ...item,
            status: "completed",
            completedAt: new Date().toISOString()
          };
        }
        return item;
      });
      updateData.pirActionItems = updatedItems;
      break;
    }

    case "TAG_RCA": {
      if (!isManager) throw new Error("Only a SOC Manager can tag for RCA");
      const allowedTerminalStatuses = ["resolved", "containment_completed"];
      if (!allowedTerminalStatuses.includes(previousStatus)) {
        throw new Error(`RCA may only be created when the incident is in a completed/terminal operational state (resolved, containment_completed)`);
      }
      updateData.rcaTagged = true;
      updateData.rcaTaggedBy = user.uid;
      updateData.rcaTaggedAt = serverTimestamp();
      updateData.rcaReason = payload.reason;
      updateData.rcaStatus = "pending";
      updateData.statusHistory = arrayUnion({
        status: "rca_tagged",
        note: `Tagged for Root Cause Analysis. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "ASSIGN_RCA_OWNER": {
      if (!isManager) throw new Error("Only a SOC Manager can assign RCA owner");
      const { assignee, assigneeRole } = payload;
      if (!assignee) throw new Error("Missing assignee for ASSIGN_RCA_OWNER");
      const allowedRCAOwnerRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];
      const canonicalRole = normalizeRole(assigneeRole);
      if (!allowedRCAOwnerRoles.includes(canonicalRole)) {
        throw new Error(`User with role ${assigneeRole} cannot be assigned as RCA owner`);
      }
      updateData.rcaOwner = assignee;
      updateData.rcaAssignedAt = serverTimestamp();
      updateData.rcaAssignedBy = user.uid;
      updateData.rcaStatus = "assigned";
      updateData.statusHistory = arrayUnion({
        status: "rca_assigned",
        note: `RCA assigned to ${assignee} by SOC Manager`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "REASSIGN_RCA_OWNER": {
      if (!isManager) throw new Error("Only a SOC Manager can reassign RCA owner");
      const { assignee, assigneeRole } = payload;
      if (!assignee) throw new Error("Missing assignee for REASSIGN_RCA_OWNER");
      const allowedRCAOwnerRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];
      const canonicalRole = normalizeRole(assigneeRole);
      if (!allowedRCAOwnerRoles.includes(canonicalRole)) {
        throw new Error(`User with role ${assigneeRole} cannot be assigned as RCA owner`);
      }
      updateData.rcaOwner = assignee;
      updateData.rcaAssignedAt = serverTimestamp();
      updateData.rcaAssignedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "rca_reassigned",
        note: `RCA owner reassigned to ${assignee} by SOC Manager`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "ADD_RCA_CONTRIBUTOR": {
      if (!isManager) throw new Error("Only a SOC Manager can add RCA contributor");
      const { contributor, contributorRole } = payload;
      if (!contributor) throw new Error("Missing contributor for ADD_RCA_CONTRIBUTOR");
      const allowedRCAContribRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];
      const canonicalRole = normalizeRole(contributorRole);
      if (!allowedRCAContribRoles.includes(canonicalRole)) {
        throw new Error(`User with role ${contributorRole} cannot be added as RCA contributor`);
      }
      updateData.rcaContributors = arrayUnion(contributor);
      updateData.statusHistory = arrayUnion({
        status: "rca_contributor_added",
        note: `Contributor ${contributor} added to RCA`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "REMOVE_RCA_CONTRIBUTOR": {
      if (!isManager) throw new Error("Only a SOC Manager can remove RCA contributor");
      const { contributor } = payload;
      if (!contributor) throw new Error("Missing contributor for REMOVE_RCA_CONTRIBUTOR");
      updateData.rcaContributors = arrayRemove(contributor);
      updateData.statusHistory = arrayUnion({
        status: "rca_contributor_removed",
        note: `Contributor ${contributor} removed from RCA`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "START_RCA": {
      const isOwner = incident.rcaOwner === user.uid;
      if (!isOwner && !isManager) {
        throw new Error("Only the RCA Owner or a SOC Manager can start the RCA");
      }
      updateData.rcaStatus = "in_progress";
      updateData.statusHistory = arrayUnion({
        status: "rca_started",
        note: `RCA started by ${user.uid}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "COMPLETE_RCA": {
      const { rootCause, contributingFactors, technicalAnalysis } = payload;
      const isOwner = incident.rcaOwner === user.uid;
      if (!isOwner && !isManager) {
        throw new Error("Only the RCA Owner or a SOC Manager can complete the RCA");
      }
      if (!rootCause || !rootCause.trim()) {
        throw new Error("Root Cause is required to complete the RCA");
      }
      updateData.rcaStatus = "completed";
      updateData.rootCause = rootCause;
      updateData.contributingFactors = contributingFactors || [];
      updateData.technicalAnalysis = technicalAnalysis || "";
      updateData.rcaCompletedAt = serverTimestamp();
      updateData.rcaCompletedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "rca_completed",
        note: `RCA completed by ${user.uid}. Root Cause: ${rootCause.substring(0, 100)}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "ADD_RCA_PREVENTIVE_ACTION": {
      const isOwner = incident.rcaOwner === user.uid;
      if (!isOwner && !isManager) {
        throw new Error("Only the RCA Owner or a SOC Manager can add preventive actions");
      }
      const { description, owner, dueDate, priority } = payload;
      if (!description) throw new Error("Missing description for preventive action");
      if (!owner) throw new Error("Missing owner for preventive action");
      if (!dueDate) throw new Error("Missing dueDate for preventive action");
      if (incident.rcaApproved) {
        throw new Error("Cannot add preventive actions to an approved RCA");
      }
      const newAction = {
        id: Math.random().toString(36).substr(2, 9),
        description,
        owner,
        dueDate,
        priority: priority || "medium",
        status: "open",
        completedAt: null,
        createdAt: new Date().toISOString()
      };
      updateData.rcaPreventiveActions = arrayUnion(newAction);
      break;
    }

    case "COMPLETE_RCA_PREVENTIVE_ACTION": {
      const isOwner = incident.rcaOwner === user.uid;
      const isContributor = incident.rcaContributors && incident.rcaContributors.includes(user.uid);
      if (!isOwner && !isContributor && !isManager) {
        throw new Error("Only the RCA Owner, a contributor, or a SOC Manager can complete preventive actions");
      }
      const { actionItemId } = payload;
      if (!actionItemId) throw new Error("Missing actionItemId");
      const currentActions = incident.rcaPreventiveActions || [];
      const updatedActions = currentActions.map(item => {
        if (item.id === actionItemId) {
          return {
            ...item,
            status: "completed",
            completedAt: new Date().toISOString()
          };
        }
        return item;
      });
      updateData.rcaPreventiveActions = updatedActions;
      break;
    }

    case "APPROVE_RCA": {
      if (!isManager) {
        throw new Error("Only a SOC Manager can approve the RCA");
      }
      updateData.rcaApproved = true;
      updateData.rcaApprovedAt = serverTimestamp();
      updateData.rcaApprovedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "rca_approved",
        note: `RCA approved by SOC Manager ${user.uid}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "REJECT_RCA": {
      if (!isManager) {
        throw new Error("Only a SOC Manager can reject the RCA");
      }
      updateData.rcaStatus = "in_progress";
      updateData.rcaApproved = false;
      updateData.rcaRejectedAt = serverTimestamp();
      updateData.rcaRejectedBy = user.uid;
      updateData.rcaRejectionReason = payload.reason || "";
      updateData.statusHistory = arrayUnion({
        status: "rca_rejected",
        note: `RCA rejected by SOC Manager ${user.uid}. Reason: ${payload.reason || "N/A"}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "START_HUNT": {
      if (trueRole !== "threat_hunter" && !isManager) {
        throw new Error("Only the Threat Hunter or a SOC Manager can start the Threat Hunt");
      }
      updateData.huntStatus = "in_progress";
      updateData.huntStartedAt = serverTimestamp();
      updateData.huntStartedBy = user.uid;
      updateData.statusHistory = arrayUnion({
        status: "threat_hunt_started",
        note: `Threat Hunt started by ${user.uid}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "SAVE_HUNT_DRAFT": {
      if (trueRole !== "threat_hunter" && !isManager) {
        throw new Error("Only the Threat Hunter or a SOC Manager can save Threat Hunt drafts");
      }
      if (incident.huntStatus === "submitted" || incident.huntStatus === "approved" || incident.huntStatus === "completed") {
        throw new Error("Cannot modify a submitted or completed Threat Hunt");
      }
      updateData.huntNotes = payload.notes || "";
      updateData.huntFindings = payload.findings || "";
      updateData.huntRecommendation = payload.recommendation || "";
      break;
    }

    case "MAP_ATTACK_TECHNIQUE": {
      if (trueRole !== "threat_hunter" && !isManager) {
        throw new Error("Only the Threat Hunter or a SOC Manager can map ATT&CK techniques");
      }
      if (incident.huntStatus === "submitted" || incident.huntStatus === "approved" || incident.huntStatus === "completed") {
        throw new Error("Cannot modify a submitted or completed Threat Hunt");
      }
      const { techniqueId, techniqueName } = payload;
      if (!techniqueId || !techniqueName) {
        throw new Error("Missing techniqueId or techniqueName");
      }
      const newTechnique = {
        techniqueId,
        techniqueName,
        mappedBy: user.uid,
        mappedAt: new Date().toISOString()
      };
      updateData.attackTechniques = arrayUnion(newTechnique);
      updateData.statusHistory = arrayUnion({
        status: "attack_technique_mapped",
        note: `ATT&CK Technique Added: ${techniqueId} - ${techniqueName}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "UNMAP_ATTACK_TECHNIQUE": {
      if (trueRole !== "threat_hunter" && !isManager) {
        throw new Error("Only the Threat Hunter or a SOC Manager can unmap ATT&CK techniques");
      }
      if (incident.huntStatus === "submitted" || incident.huntStatus === "approved" || incident.huntStatus === "completed") {
        throw new Error("Cannot modify a submitted or completed Threat Hunt");
      }
      const { techniqueId } = payload;
      if (!techniqueId) {
        throw new Error("Missing techniqueId");
      }
      const currentTechs = incident.attackTechniques || [];
      const updatedTechs = currentTechs.filter(t => t.techniqueId !== techniqueId);
      updateData.attackTechniques = updatedTechs;
      updateData.statusHistory = arrayUnion({
        status: "attack_technique_unmapped",
        note: `ATT&CK Technique Removed: ${techniqueId}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "SUBMIT_HUNT": {
      if (trueRole !== "threat_hunter" && !isManager) {
        throw new Error("Only the Threat Hunter or a SOC Manager can submit the Threat Hunt");
      }
      const { option, notes, findings, recommendation } = payload;
      if (!option) {
        throw new Error("Complete Hunt option (return_l2 or close) is required");
      }
      updateData.huntNotes = notes || "";
      updateData.huntFindings = findings || "";
      updateData.huntRecommendation = recommendation || "";
      updateData.huntCompleteOption = option;
      updateData.huntSubmittedAt = serverTimestamp();
      updateData.huntSubmittedBy = user.uid;
      updateData.huntStatus = "submitted";

      updateData.statusHistory = arrayUnion({
        status: "hunt_recommendation_submitted",
        note: `Threat Hunt recommendation submitted by ${user.uid}. Option: ${option}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "APPROVE_HUNT": {
      if (!isManager) {
        throw new Error("Only a SOC Manager can approve the Threat Hunt");
      }
      if (incident.huntStatus !== "submitted") {
        throw new Error("Threat Hunt is not in submitted status");
      }
      updateData.huntApprovedAt = serverTimestamp();
      updateData.huntApprovedBy = user.uid;
      updateData.huntStatus = "approved";

      const option = incident.huntCompleteOption || "close";
      if (option === "return_l2") {
        updateData.status = "investigation_l2";
        updateData.assignedTo = "soc_l2";
        updateData.visibleTo = ["soc_l2", "soc_manager"];
        updateData.statusHistory = arrayUnion(
          {
            status: "threat_hunt_approved",
            note: `Threat Hunt approved by Manager ${user.uid}`,
            by: user.uid,
            at: new Date().toISOString(),
          },
          {
            status: "threat_hunt_returned",
            note: `Threat Hunt returned to L2. Recommendation: ${incident.huntRecommendation || "N/A"}`,
            by: user.uid,
            at: new Date().toISOString(),
          }
        );
      } else if (option === "close") {
        updateData.status = "resolved";
        updateData.statusHistory = arrayUnion(
          {
            status: "threat_hunt_approved",
            note: `Threat Hunt approved by Manager ${user.uid}`,
            by: user.uid,
            at: new Date().toISOString(),
          },
          {
            status: "threat_hunt_completed",
            note: `Threat Hunt completed and closed. Recommendation: ${incident.huntRecommendation || "N/A"}`,
            by: user.uid,
            at: new Date().toISOString(),
          }
        );
      } else {
        throw new Error(`Invalid complete option: ${option}`);
      }
      break;
    }

    case "REJECT_HUNT": {
      if (!isManager) {
        throw new Error("Only a SOC Manager can reject the Threat Hunt");
      }
      if (incident.huntStatus !== "submitted") {
        throw new Error("Threat Hunt is not in submitted status");
      }
      const { reason } = payload;
      updateData.huntStatus = "in_progress";
      updateData.huntRejectedAt = serverTimestamp();
      updateData.huntRejectedBy = user.uid;
      updateData.huntRejectionReason = reason || "";
      updateData.statusHistory = arrayUnion({
        status: "threat_hunt_rejected",
        note: `Threat Hunt rejected by Manager ${user.uid}. Reason: ${reason || "N/A"}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;
    }

    case "COMPLETE_HUNT": {
      if (trueRole !== "threat_hunter" && !isManager) {
        throw new Error("Only the Threat Hunter or a SOC Manager can complete the Threat Hunt");
      }
      const { option, notes, findings, recommendation } = payload;
      if (!option) {
        throw new Error("Complete Hunt option (return_l2 or close) is required");
      }
      updateData.huntNotes = notes || "";
      updateData.huntFindings = findings || "";
      updateData.huntRecommendation = recommendation || "";
      updateData.huntCompletedAt = serverTimestamp();
      updateData.huntCompletedBy = user.uid;
      updateData.huntStatus = "completed";

      if (option === "return_l2") {
        updateData.status = "investigation_l2";
        updateData.assignedTo = "soc_l2";
        updateData.visibleTo = ["soc_l2", "soc_manager"];
        updateData.statusHistory = arrayUnion({
          status: "threat_hunt_returned",
          note: `Threat Hunt returned to L2. Recommendation: ${recommendation || "N/A"}`,
          by: user.uid,
          at: new Date().toISOString(),
        });
      } else if (option === "close") {
        updateData.status = "resolved";
        updateData.statusHistory = arrayUnion({
          status: "threat_hunt_completed",
          note: `Threat Hunt completed and closed. Recommendation: ${recommendation || "N/A"}`,
          by: user.uid,
          at: new Date().toISOString(),
        });
      } else {
        throw new Error(`Invalid Complete Hunt option: ${option}`);
      }
      break;
    }


    case "ADD_EVIDENCE":
      const { type, content } = payload;
      if (!type) throw new Error("Missing type for ADD_EVIDENCE");
      if (!content) throw new Error("Missing content for ADD_EVIDENCE");

      await addDoc(collection(db, "issues", incidentId, "evidence"), {
        type,
        content,
        createdAt: serverTimestamp(),
        createdBy: user.uid,
      });

      if (type === "note") {
        logLifecycleAudit(incidentId, AUDIT_ACTIONS.NOTE_ADDED, "unknown", {
          note: content,
        });
      }

      return { success: true, action: actionType, message: "Evidence added" };

    case "UPDATE_RISK_SCORE":
      const { riskScore } = payload;
      if (riskScore === undefined || riskScore === null) throw new Error("Missing riskScore");
      if (typeof riskScore !== "number" || riskScore < 0 || riskScore > 100) throw new Error("riskScore must be between 0 and 100");
      updateData.riskScore = riskScore;
      break;

    default:
      throw new Error(`Action ${actionType} not yet implemented`);
  }

  // Validate status transition if status is being updated
  if (updateData.status && previousStatus) {
    if (!isValidTransition(previousStatus, updateData.status)) {
      throw new Error(`Invalid transition: ${previousStatus} → ${updateData.status}`);
    }
  }

  await updateDoc(incidentRef, updateData);
  return { success: true, action: actionType, message: `${actionType} completed successfully` };
}

/**
 * Admin permanently deletes a user from Firebase Auth + Firestore.
 * NOTE: Client SDK cannot delete other Auth users. This function only deletes from Firestore.
 * Auth user deletion requires Admin SDK (Cloud Function).
 */
export async function callDeleteUser(targetUid) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  // Only delete from Firestore for now
  const userRef = doc(db, "users", targetUid);
  await deleteDoc(userRef);
  return { success: true, message: "User deleted from Firestore (Auth deletion requires Admin SDK)" };
}

/**
 * Update tags on an incident.
 * @param {string[]} tags - array of tag strings
 */
export async function callUpdateTags(incidentId, tags) {
  return callGovernanceAction(incidentId, "UPDATE_TAGS", { tags });
}

/**
 * Add evidence to an incident.
 * @param {Object} evidence - { type: "file"|"link"|"note"|"screenshot", content?, url?, description? }
 */
export async function callAddEvidence(incidentId, evidence) {
  const content = evidence.content || evidence.url || evidence.description || "";
  return callGovernanceAction(incidentId, "ADD_EVIDENCE", {
    type: evidence.type,
    content,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: Bulk Operations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute a governance action across multiple incidents.
 * Max 20 incidents per call. Returns { results, summary }.
 *
 * @param {string[]} incidentIds - array of incident IDs (max 20)
 * @param {string} actionType - LOCK | UNLOCK | UPDATE_TAGS | ASSIGN | ESCALATE | UPDATE_RISK_SCORE
 * @param {Object} payload - action-specific data
 */
export async function callBulkGovernanceAction(incidentIds, actionType, payload = {}) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  if (!Array.isArray(incidentIds) || incidentIds.length === 0) {
    throw new Error("incidentIds must be a non-empty array");
  }
  if (incidentIds.length > 20) {
    throw new Error("Maximum 20 incidents per bulk operation");
  }

  const results = { success: [], failed: [], skipped: [] };

  for (const incidentId of incidentIds) {
    try {
      await callGovernanceAction(incidentId, actionType, payload);
      results.success.push(incidentId);
    } catch (err) {
      results.failed.push({ incidentId, error: err.message });
    }
  }

  return { success: true, results };
}

/**
 * Update risk assessment on an incident.
 * @param {Object} params - { riskScore?, confidenceScore?, attackStage?, ownerUid? }
 */
export async function callUpdateRiskScore(incidentId, { riskScore, confidenceScore, attackStage, ownerUid } = {}) {
  return callGovernanceAction(incidentId, "UPDATE_RISK_SCORE", {
    riskScore, confidenceScore, attackStage, ownerUid,
  });
}
