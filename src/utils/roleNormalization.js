/**
 * ======================================================================
 * ROLE NORMALIZATION — Re-export Adapter
 * ======================================================================
 *
 * This file delegates ALL normalization to the canonical authority:
 *   ./normalizeRole.js
 *
 * It exists to preserve existing import paths. Files importing from
 * this module continue to work without changes.
 *
 * DO NOT add independent normalization logic here.
 * ======================================================================
 */

import {
  normalizeRole,
  normalizeRoles,
  CANONICAL_ROLES,
  isCanonicalRole,
  getRoleDisplayLabel,
  normalizeIncidentParty,
} from "./normalizeRole";
import { getAuth } from "firebase/auth";

// Re-export canonical functions
export {
  normalizeRole,
  normalizeRoles,
  CANONICAL_ROLES,
  isCanonicalRole,
  getRoleDisplayLabel,
  normalizeIncidentParty,
};

/**
 * Legacy ROLE_MAP — kept for backward compatibility with code that reads it.
 * All values map to canonical roles.
 */
export const ROLE_MAP = Object.freeze({
  // Legacy numeric variants
  "soc_11": "soc_l1",
  "soc_12": "soc_l2",
  "soc_13": "soc_manager",

  // Common variants
  "incident_response": "ir",
  "incidentresponse": "ir",
  "ir_team": "ir",
  "IR Team": "ir",
  "SOC L1": "soc_l1",
  "SOC L2": "soc_l2",
  "SOC Manager": "soc_manager",
  "SOC_MANAGER": "soc_manager",

  // Standardized roles (self-mapping)
  "soc_l1": "soc_l1",
  "soc_l2": "soc_l2",
  "soc_manager": "soc_manager",
  "ir": "ir",
  "admin": "admin",
  "threat_hunter": "threat_hunter",
  "student": "student",
});

/**
 * Check if incident is visible to a role.
 * Checks visibleTo, assignedTo, and escalatedTo fields.
 *
 * @param {object} incident - Incident object
 * @param {string} role - Role to check visibility for
 * @returns {boolean}
 */
export function isVisibleToRole(incident, role) {
  const normalizedRole = normalizeRole(role);
  if (!normalizedRole) return false;

  const normalizedAssignedTo = normalizeRole(incident.assignedTo);
  const normalizedEscalatedTo = normalizeRole(incident.escalatedTo);
  const normalizedVisibleTo = incident.visibleTo ? normalizeRoles(incident.visibleTo) : [];

  // Decoupled PIR visibility: Owner or Contributors gain direct visibility
  // Decoupled RCA visibility: Owner or Contributors gain direct visibility
  try {
    const auth = getAuth();
    const currentUid = auth.currentUser?.uid;
    if (currentUid) {
      if (incident.pirOwner === currentUid) return true;
      if (incident.pirContributors && incident.pirContributors.includes(currentUid)) return true;
      if (incident.rcaOwner === currentUid) return true;
      if (incident.rcaContributors && incident.rcaContributors.includes(currentUid)) return true;
      // Threat Hunter Historical Visibility
      if (incident.huntStartedBy === currentUid || incident.huntCompletedBy === currentUid || incident.huntSubmittedBy === currentUid) return true;
    }
  } catch (e) {
    // Fail-safe fallback if Firebase Auth is not yet initialized
  }

  return (
    normalizedVisibleTo.includes(normalizedRole) ||
    normalizedAssignedTo === normalizedRole ||
    normalizedEscalatedTo === normalizedRole
  );
}

/**
 * Check if role is normalized (canonical).
 *
 * @param {string} role
 * @returns {boolean}
 */
export function isNormalizedRole(role) {
  return isCanonicalRole(role);
}

/**
 * Get visibleTo array for a specific status.
 *
 * @param {string} status - Current incident status
 * @returns {string[]} Array of canonical roles that should see this incident
 */
export function getVisibleToForStatus(status) {
  const statusVisibilityRules = {
    // Initial states
    open: ["soc_l1", "soc_l2", "soc_manager"],
    assigned: ["soc_l1", "soc_l2", "soc_manager"],
    in_progress: ["soc_l1", "soc_l2", "soc_manager"],
    escalation_requested: ["soc_l1", "soc_l2", "soc_manager"],

    // Investigation states
    confirmed_threat: ["soc_l2", "soc_manager"],
    false_positive: ["soc_l2", "soc_manager"],

    // Escalation states
    escalation_pending: ["soc_l2", "soc_manager"],
    escalation_approved: ["soc_l2", "soc_manager", "ir"],
    escalation_denied: ["soc_l2", "soc_manager"],

    // IR investigation
    ir_in_progress: ["soc_manager", "ir"],

    // Containment workflow
    containment_pending_approval: ["soc_l2", "soc_manager"],
    containment_in_progress: ["soc_manager", "ir"],
    containment_action_submitted: ["soc_l2", "soc_manager", "ir"],
    containment_approved: ["soc_l2", "soc_manager", "ir"],
    containment_rejected: ["soc_l2", "soc_manager", "ir"],
    containment_review_again: ["soc_l2", "soc_manager", "ir"],
    containment_completed: ["soc_l2", "soc_manager"],
    containment_executed: ["soc_l2", "soc_manager", "ir"],

    // L2 investigation
    investigation_l2: ["soc_l2", "soc_manager"],

    // Threat hunt state
    threat_hunt: ["soc_manager", "threat_hunter"],

    // Final states
    resolved: ["soc_l1", "soc_l2", "soc_manager", "ir"],
    reopened: ["soc_l1", "soc_l2", "soc_manager"],

    // Legacy states
    containment_pending: ["soc_l2", "soc_manager", "ir"],
    contained: ["soc_l2", "soc_manager", "ir"],
    in_review: ["soc_l1", "soc_l2", "soc_manager"],
  };

  return statusVisibilityRules[status] || ["soc_l1", "soc_l2", "soc_manager", "ir"];
}

/**
 * Check if incident should be visible to role based on strict status rules.
 *
 * @param {object} incident - Incident object
 * @param {string} role - Role to check visibility for
 * @returns {boolean}
 */
export function isVisibleToRoleStrict(incident, role) {
  const normalizedRole = normalizeRole(role);
  if (!normalizedRole) return false;

  const status = incident.status || "open";
  const expectedVisibleTo = getVisibleToForStatus(status);

  return expectedVisibleTo.includes(normalizedRole);
}
