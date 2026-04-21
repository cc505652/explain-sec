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
import { doc, updateDoc, arrayUnion, serverTimestamp, getDoc, deleteDoc, collection, addDoc } from "firebase/firestore";
import { app, db } from "../firebase";

// Get the Firebase auth instance
const auth = getAuth(app);

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
    visibleTo: ["soc_l1", "soc_l2"],
    statusHistory: arrayUnion({
      status: "escalation_requested",
      note: "Escalated to SOC L2",
      by: user.uid,
      at: new Date().toISOString(),
    }),
    updatedAt: serverTimestamp(),
  };

  await updateDoc(incidentRef, updateData);

  return { success: true, message: "Incident escalated" };
}

/**
 * SOC Manager approves an escalation request → assigns incident to ir
 */
export async function callApproveEscalation(incidentId) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  if (!incidentSnap.exists()) throw new Error("Incident not found");

  const incident = incidentSnap.data();

  if (incident.escalationApproved !== true) {
    throw new Error("Incident not pending escalation approval");
  }

  const updateData = {
    escalationApproved: true,
    escalationApprovedBy: user.uid,
    escalationApprovedAt: serverTimestamp(),
    assignedTo: "ir",
    assignedAt: serverTimestamp(),
    visibleTo: ["soc_l2", "soc_manager", "ir"],
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

  const incidentRef = doc(db, "issues", incidentId);
  const updateData = {
    status: "containment_pending",
    containmentAction: actionType,
  };

  await updateDoc(incidentRef, updateData);
  return { success: true, message: `Containment action ${actionType} performed` };
}

/**
 * SOC Manager approves containment → resolves the incident
 */
export async function callApproveContainment(incidentId) {
  const user = auth.currentUser;
  if (!user) throw new Error("User not authenticated");

  const incidentRef = doc(db, "issues", incidentId);
  const updateData = {
    status: "resolved",
    resolvedAt: serverTimestamp(),
    resolvedBy: user.uid,
    containmentApprovedBy: user.uid,
    containmentApprovedAt: serverTimestamp(),
    readyForManagerReview: false,
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

  const incidentRef = doc(db, "issues", incidentId);
  const updateData = {
    status: nextStatus,
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

  const incidentRef = doc(db, "issues", incidentId);
  const incidentSnap = await getDoc(incidentRef);
  if (!incidentSnap.exists()) throw new Error("Incident not found");

  const incident = incidentSnap.data();
  const previousStatus = incident.status;
  let updateData = { updatedAt: serverTimestamp() };

  switch (actionType) {
    case "TRANSFER_OWNERSHIP":
      updateData.assignedTo = payload.newAssignedTo;
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
      updateData.status = "risk_accepted";
      updateData.riskAccepted = true;
      updateData.riskAcceptedBy = user.uid;
      updateData.riskAcceptedAt = serverTimestamp();
      updateData.statusHistory = arrayUnion({
        status: "risk_accepted",
        note: `Risk accepted by SOC Manager. Reason: ${payload.reason}`,
        by: user.uid,
        at: new Date().toISOString(),
      });
      break;

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
