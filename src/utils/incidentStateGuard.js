// Incident State Machine Guard for SOC Platform
// Prevents illegal workflow transitions

// ─── COMPLETE INCIDENT LIFECYCLE ───────────────────────────────────────────
// open → in_progress → confirmed_threat → escalation_pending
//       ↓                                         ↓
//   false_positive                       escalation_approved
//       ↓                                         ↓
//    resolved                            ir_in_progress
//                                                 ↓
//                                     containment_in_progress
//                                                 ↓
//                                     containment_action_submitted
//                                                 ↓
//                                     containment_approved (manager approves)
//                                     containment_rejected (manager rejects)
//                                     containment_review_again (manager asks for review)
//                                                 ↓
//                                     containment_executed (IR executes)
//                                                 ↓
//                                             resolved
//                                             ↓
//                                          reopened
// ───────────────────────────────────────────────────────────────────────────

export const INCIDENT_TRANSITIONS = {

  open: [
    "in_progress",
    "assigned",
    "false_positive"
  ],

  assigned: [
    "in_progress",
    "open",
    "false_positive",
    "escalation_pending",
    "escalation_requested",
    "confirmed_threat"
  ],

  in_progress: [
    "confirmed_threat",
    "false_positive",
    "assigned",
    "escalation_pending",
    "escalation_requested",
    "containment_pending"
  ],

  confirmed_threat: [
    "escalation_pending",
    "in_progress",
    "false_positive",
    "assigned"
  ],

  escalation_pending: [
    "escalation_approved",   // Manager approves → IR assigned
    "in_progress",           // Manager denies → back to investigation
    "confirmed_threat",      // Alternative denial path
    "assigned"               // Reassign without escalation
  ],

  escalation_approved: [
    "ir_in_progress",
    "containment_pending",
    "in_progress"            // IR fallback
  ],

  // Alias for "assigned to IR Team post-approval"
  ir_in_progress: [
    "containment_in_progress",
    "in_progress"
  ],

  // Enterprise-grade containment workflow
  containment_in_progress: [
    "containment_action_submitted",
    "in_progress"
  ],

  containment_action_submitted: [
    "containment_approved",      // Manager approves action
    "containment_rejected",      // Manager rejects action
    "containment_review_again",   // Manager asks for review
    "in_progress"                // IR cancels action
  ],

  containment_approved: [
    "containment_executed"       // IR executes approved action
  ],

  containment_rejected: [
    "containment_in_progress",   // IR resubmits action
    "in_progress"                // IR abandons containment
  ],

  containment_review_again: [
    "containment_in_progress",   // IR resubmits action
    "in_progress"                // IR abandons containment
  ],

  containment_executed: [
    "resolved",
    "in_progress"                // Re-investigate if containment insufficient
  ],

  // NEW: Manager-approved final state (no execution step)
  containment_completed: [
    "resolved",
    "in_progress"                // Re-investigate if needed
  ],

  // Legacy compatibility - keep for existing data
  containment_pending: [
    "contained",
    "containment_approved",      // alias
    "in_progress"
  ],

  contained: [
    "resolved",
    "in_progress"
  ],

  // L2 containment request state
  containment_pending_approval: [
    "containment_in_progress",   // Manager approves → IR sees incident
    "investigation_l2"           // Manager rejects → back to L2
  ],

  // L2 investigation state after rejection
  investigation_l2: [
    "in_progress",
    "containment_pending_approval",  // L2 can request again
    "confirmed_threat"
  ],

  false_positive: [
    "resolved",
    "reopened",
    "open"                   // allow reopening false positives
  ],

  resolved: [
    "reopened"
  ],

  reopened: [
    "open",
    "in_progress",
    "assigned"
  ],

  // Legacy compatibility: "in_review" was used in older code
  in_review: [
    "confirmed_threat",
    "false_positive",
    "assigned",
    "in_progress"
  ]

};

// ── Guard Function ───────────────────────────────────────────────────────────
export function isValidTransition(currentStatus, nextStatus) {
  // Same-state is always valid (idempotent writes)
  if (currentStatus === nextStatus) return true;

  const allowed = INCIDENT_TRANSITIONS[currentStatus];
  if (!allowed) return false;

  return allowed.includes(nextStatus);
}

// ── Role-Based Action Validation ─────────────────────────────────────────────
export function canPerformAction(userRole, currentStatus, action) {
  const rolePermissions = {
    L1: {
      allowedTransitions: {
        open: ["in_progress", "assigned"],
        assigned: ["in_progress", "confirmed_threat", "false_positive"],
        in_progress: ["confirmed_threat", "false_positive"]
      },
      allowedActions: ["start_investigation", "start_triage", "confirm_threat", "mark_false_positive", "escalate_to_l2", "add_note"]
    },
    L2: {
      allowedTransitions: {
        assigned: ["in_progress", "confirmed_threat", "escalation_pending"],
        in_progress: ["confirmed_threat", "escalation_pending", "false_positive"],
        confirmed_threat: ["containment_pending_approval", "escalation_pending", "in_progress"],
        investigation_l2: ["containment_pending_approval", "in_progress", "confirmed_threat"]
      },
      allowedActions: ["request_escalation", "continue_investigation", "confirm_threat", "mark_false_positive", "escalate_to_ir", "add_note", "adjust_severity", "request_containment"]
    },
    MANAGER: {
      allowedTransitions: {
        escalation_pending: ["escalation_approved", "in_progress", "confirmed_threat"],
        containment_pending_approval: ["containment_in_progress", "investigation_l2"],
        containment_action_submitted: ["containment_completed", "containment_rejected", "containment_review_again"],
        containment_completed: ["resolved", "in_progress"],
        containment_approved: [], // Legacy - IR executes
        containment_rejected: [], // IR resubmits
        containment_review_again: [], // IR resubmits
        containment_executed: ["resolved"],
        resolved: ["reopened"],
        reopened: ["in_progress", "assigned"]
      },
      allowedActions: [
        "approve_escalation", "deny_escalation",
        "approve_containment_request", "reject_containment_request",
        "approve_containment_action", "reject_containment_action", "request_containment_review",
        "resolve_incident", "reopen_incident",
        "lock_incident", "unlock_incident",
        "assign_ir", "override_triage"
      ]
    },
    IR: {
      allowedTransitions: {
        assigned: ["in_progress", "containment_in_progress", "ir_in_progress"],
        escalation_approved: ["containment_in_progress", "ir_in_progress"],
        containment_in_progress: ["containment_action_submitted"],
        containment_action_submitted: [], // Manager decides
        containment_approved: ["containment_executed"],
        containment_rejected: ["containment_in_progress"],
        containment_review_again: ["containment_in_progress"],
        containment_completed: [], // Final state - no IR action needed
        containment_executed: ["resolved"],
        ir_in_progress: ["containment_in_progress"],
        in_progress: ["containment_in_progress"]
      },
      allowedActions: ["submit_containment_action", "update_containment_action", "execute_containment", "investigate", "block_ip", "isolate_host", "disable_account", "patch_system", "kill_process"]
    },
    soc_l1: {
      allowedTransitions: {
        open: ["in_progress", "assigned"],
        assigned: ["in_progress", "confirmed_threat", "false_positive"],
        in_progress: ["confirmed_threat", "false_positive"]
      },
      allowedActions: ["start_triage", "confirm_threat", "mark_false_positive", "escalate_to_l2", "add_note"]
    },
    soc_l2: {
      allowedTransitions: {
        assigned: ["in_progress", "confirmed_threat", "escalation_pending"],
        in_progress: ["confirmed_threat", "escalation_pending", "false_positive"],
        confirmed_threat: ["escalation_pending", "in_progress"]
      },
      allowedActions: ["request_escalation", "continue_investigation", "confirm_threat", "mark_false_positive", "escalate_to_ir", "add_note", "adjust_severity"]
    },
    incident_response: {
      allowedTransitions: {
        assigned: ["in_progress", "containment_pending"],
        escalation_approved: ["containment_pending", "in_progress"],
        ir_in_progress: ["containment_pending"],
        in_progress: ["containment_pending"],
        containment_pending: ["contained"]
      },
      allowedActions: ["perform_containment", "investigate", "block_ip", "isolate_host", "disable_account", "patch_system", "kill_process"]
    }
  };

  const permissions = rolePermissions[userRole];
  if (!permissions) return false;

  if (!permissions.allowedActions.includes(action)) return false;

  const allowedTransitions = permissions.allowedTransitions[currentStatus];
  if (allowedTransitions && !allowedTransitions.includes(action)) return false;

  return true;
}

// ── Status Lock Validation ───────────────────────────────────────────────────
export function isStatusLocked(currentStatus, action = null) {
  if (currentStatus === "resolved" && action !== "reopen" && action !== "reopen_incident") {
    return true;
  }
  return false;
}

// ── Full Transition Validation ───────────────────────────────────────────────
export function validateTransition(currentStatus, nextStatus, userRole = null, action = null) {
  if (!isValidTransition(currentStatus, nextStatus)) {
    return {
      valid: false,
      error: `Invalid transition: ${currentStatus} → ${nextStatus}. Check incident workflow state.`
    };
  }

  if (isStatusLocked(currentStatus, action)) {
    return {
      valid: false,
      error: "Incident resolved. Use 'Reopen Incident' to continue."
    };
  }

  if (userRole && action) {
    if (!canPerformAction(userRole, currentStatus, action)) {
      return {
        valid: false,
        error: `Action '${action}' not allowed for role '${userRole}' at status '${currentStatus}'`
      };
    }
  }

  return { valid: true, error: null };
}

// ── Expected Workflow States per Role ────────────────────────────────────────
export const WORKFLOW_STATES = {
  L1_WORKFLOW: ["open", "assigned", "in_progress", "confirmed_threat", "false_positive"],
  L2_WORKFLOW: ["assigned", "in_progress", "confirmed_threat", "escalation_pending", "containment_pending_approval", "investigation_l2"],
  MANAGER_WORKFLOW: ["escalation_pending", "escalation_approved", "containment_pending_approval", "containment_action_submitted", "containment_completed", "containment_rejected", "containment_review_again", "resolved"],
  IR_WORKFLOW: ["assigned", "escalation_approved", "ir_in_progress", "containment_in_progress", "containment_action_submitted", "containment_rejected", "containment_review_again"]
};

// ── Status Display Labels ────────────────────────────────────────────────────
export const STATUS_LABELS = {
  open: "Open",
  assigned: "Assigned",
  in_progress: "In Progress",
  in_review: "In Review",
  confirmed_threat: "Confirmed Threat",
  escalation_requested: "Escalation Requested",
  escalation_pending: "Escalation Pending",
  escalation_approved: "Escalation Approved",
  ir_in_progress: "IR Investigation",
  containment_in_progress: "Containment In Progress",
  containment_action_submitted: "Action Submitted - Manager Review",
  containment_approved: "Action Approved - Ready to Execute",
  containment_rejected: "Action Rejected",
  containment_review_again: "Action Review Requested",
  containment_executed: "Containment Executed",
  containment_completed: "Containment Completed",
  // Legacy compatibility
  containment_pending: "Containment Pending",
  contained: "Contained",
  false_positive: "False Positive",
  resolved: "Resolved",
  reopened: "Reopened",
  // L2 workflow states
  containment_pending_approval: "Containment Request - Manager Review",
  investigation_l2: "L2 Investigation",
  // Phase 2: governance post-resolution states
  pir_pending: "PIR Pending",
  rca_pending: "RCA Pending",
  rca_completed: "RCA Completed",
  risk_accepted: "Risk Accepted",
  threat_hunt: "Threat Hunt",
};

// ── Phase 2: Re-export from riskEngine for convenience ────────────────────
export { ATTACK_STAGES, ATTACK_STAGE_OPTIONS, getRiskPill, getAttackStageDisplay, getMitreInfo, getIncidentAging } from "./riskEngine";
