/**
 * ======================================================================
 * CENTRALIZED PERMISSION ENGINE — Foundation Layer
 * ======================================================================
 *
 * Phase: FOUNDATION (additive only — no existing behavior modified)
 *
 * PURPOSE:
 *   Provides a canonical, auditable permission abstraction that future
 *   phases can use to replace scattered inline role checks across the
 *   platform. Both can coexist safely.
 *
 * DESIGN:
 *   - Explicit permission constants (not magic strings)
 *   - Explicit role → permission-set mappings (not numeric thresholds)
 *   - Safe defaults: unknown roles/permissions → false (deny)
 *   - canUser(user, permission) for component-level convenience
 *
 * FUTURE PHASES:
 *   - Phase 2: Migrate ProtectedRoute to use canUser()
 *   - Phase 3: Replace inline role === "admin" checks in dashboards
 *   - Phase 4: Add dynamic permission overrides (Firestore-backed)
 *   - Phase 5: Audit logging integration
 *
 * BACKWARD COMPATIBILITY:
 *   This module ADDS a new abstraction. It does NOT modify, replace,
 *   or interfere with:
 *     - src/utils/normalizeRole.js  (role normalization)
 *     - src/utils/incidentStateGuard.js  (state machine)
 *     - src/App.jsx  (routing / ProtectedRoute)
 *     - Any component-level inline role checks
 *
 * ======================================================================
 */

import { normalizeRole } from "../utils/normalizeRole";

// ─── CANONICAL PERMISSION CONSTANTS ──────────────────────────────────────────
//
// Every permission in the platform should be declared here as a constant.
// Components import these constants instead of using raw strings, which
// prevents typo-driven security bugs and enables IDE auto-complete.
//
// Naming convention: VERB_NOUN  (e.g., APPROVE_ESCALATION)
// ─────────────────────────────────────────────────────────────────────────────

export const PERMISSIONS = Object.freeze({

  // ── Escalation Workflow ─────────────────────────────────────────────────
  /** Approve an escalation request (L2 → IR handoff) */
  APPROVE_ESCALATION:       "approve_escalation",
  /** Reject / deny an escalation request */
  REJECT_ESCALATION:        "reject_escalation",

  // ── Containment Workflow ────────────────────────────────────────────────
  /** Approve a containment action submitted by IR */
  APPROVE_CONTAINMENT:      "approve_containment",
  /** Reject a containment action submitted by IR */
  REJECT_CONTAINMENT:       "reject_containment",
  /** Request containment (L2 initiates) */
  REQUEST_CONTAINMENT:      "request_containment",
  /** Execute an approved containment action (IR performs) */
  EXECUTE_CONTAINMENT:      "execute_containment",

  // ── Incident Management ─────────────────────────────────────────────────
  /** Reassign an incident to a different analyst / team */
  REASSIGN_INCIDENT:        "reassign_incident",
  /** Close / resolve an incident */
  CLOSE_INCIDENT:           "close_incident",
  /** Reopen a resolved incident */
  REOPEN_INCIDENT:          "reopen_incident",
  /** Submit a new incident */
  SUBMIT_INCIDENT:          "submit_incident",
  /** Start investigation on an incident */
  START_INVESTIGATION:      "start_investigation",
  /** Escalate an incident to a higher tier */
  ESCALATE_INCIDENT:        "escalate_incident",

  // ── Triage & Investigation ──────────────────────────────────────────────
  /** Adjust incident severity */
  ADJUST_SEVERITY:          "adjust_severity",
  /** Add evidence artifacts to an incident */
  ADD_EVIDENCE:             "add_evidence",
  /** Update triage classification */
  UPDATE_TRIAGE:            "update_triage",
  /** Confirm an alert as a true threat */
  CONFIRM_THREAT:           "confirm_threat",
  /** Mark an alert as false positive */
  MARK_FALSE_POSITIVE:      "mark_false_positive",

  // ── Governance & Compliance ─────────────────────────────────────────────
  /** View governance dashboards and compliance data */
  VIEW_GOVERNANCE:          "view_governance",
  /** Lock an incident (prevent further changes) */
  LOCK_INCIDENT:            "lock_incident",
  /** Unlock a locked incident */
  UNLOCK_INCIDENT:          "unlock_incident",
  /** Override a triage or workflow decision */
  OVERRIDE_DECISION:        "override_decision",
  /** Override SLA timer */
  SLA_OVERRIDE:             "sla_override",
  /** Tag incident for Post-Incident Review */
  TAG_PIR:                  "tag_pir",
  /** Tag incident for Root Cause Analysis */
  TAG_RCA:                  "tag_rca",
  /** Accept risk and close without full remediation */
  ACCEPT_RISK:              "accept_risk",

  // ── Analytics ───────────────────────────────────────────────────────────
  /** View analytics dashboards and reports */
  VIEW_ANALYTICS:           "view_analytics",
  /** Export analytics data */
  EXPORT_ANALYTICS:         "export_analytics",

  // ── Administration ──────────────────────────────────────────────────────
  /** Manage user accounts (create, update, disable) */
  MANAGE_USERS:             "manage_users",
  /** Manage role assignments */
  MANAGE_ROLES:             "manage_roles",
  /** View audit logs */
  VIEW_AUDIT_LOGS:          "view_audit_logs",

  // ── Team Management ─────────────────────────────────────────────────────
  /** View team fatigue metrics */
  VIEW_TEAM_FATIGUE:        "view_team_fatigue",
  /** View own fatigue metrics */
  VIEW_OWN_FATIGUE:         "view_own_fatigue",
  /** Perform bulk operations on incidents */
  BULK_OPERATIONS:          "bulk_operations",
});


// ─── CANONICAL ROLES ─────────────────────────────────────────────────────────
//
// Mirrors the canonical roles from normalizeRole.js.
// Defined here to avoid a circular import and to keep the permission
// engine self-contained.
// ─────────────────────────────────────────────────────────────────────────────

export const ROLES = Object.freeze({
  SOC_L1:         "soc_l1",
  SOC_L2:         "soc_l2",
  SOC_MANAGER:    "soc_manager",
  IR:             "ir",
  ADMIN:          "admin",
  THREAT_HUNTER:  "threat_hunter",
  STUDENT:        "student",
});


// ─── ROLE → PERMISSION MAPPING ───────────────────────────────────────────────
//
// Explicit set-based mapping. Each role lists the permissions it holds.
// This is intentionally MORE readable and auditable than a numeric-level
// threshold approach.
//
// Higher-privilege roles DO NOT automatically inherit lower-role permissions.
// Every role's permission set is explicit and self-contained. This prevents
// accidental privilege leakage when a new permission is added.
//
// To grant a permission to multiple roles, add it to each role's set.
// ─────────────────────────────────────────────────────────────────────────────

const P = PERMISSIONS; // shorthand for readability

const ROLE_PERMISSION_MAP = Object.freeze({

  // ── Student ─────────────────────────────────────────────────────────────
  // Can submit incidents and view their own. No operational permissions.
  [ROLES.STUDENT]: Object.freeze(new Set([
    P.SUBMIT_INCIDENT,
  ])),

  // ── SOC Analyst L1 ─────────────────────────────────────────────────────
  // Front-line triage. Can investigate, classify, and escalate to L2.
  [ROLES.SOC_L1]: Object.freeze(new Set([
    P.SUBMIT_INCIDENT,
    P.START_INVESTIGATION,
    P.CONFIRM_THREAT,
    P.MARK_FALSE_POSITIVE,
    P.ESCALATE_INCIDENT,
    P.ADD_EVIDENCE,
    P.UPDATE_TRIAGE,
    P.VIEW_OWN_FATIGUE,
  ])),

  // ── SOC Analyst L2 ─────────────────────────────────────────────────────
  // Deeper investigation. Can request escalation to IR and containment.
  [ROLES.SOC_L2]: Object.freeze(new Set([
    P.SUBMIT_INCIDENT,
    P.START_INVESTIGATION,
    P.CONFIRM_THREAT,
    P.MARK_FALSE_POSITIVE,
    P.ESCALATE_INCIDENT,
    P.ADD_EVIDENCE,
    P.UPDATE_TRIAGE,
    P.ADJUST_SEVERITY,
    P.REQUEST_CONTAINMENT,
    P.VIEW_OWN_FATIGUE,
  ])),

  // ── SOC Manager ─────────────────────────────────────────────────────────
  // Operational oversight. Approves escalations, containment, governance.
  [ROLES.SOC_MANAGER]: Object.freeze(new Set([
    P.APPROVE_ESCALATION,
    P.REJECT_ESCALATION,
    P.APPROVE_CONTAINMENT,
    P.REJECT_CONTAINMENT,
    P.REASSIGN_INCIDENT,
    P.CLOSE_INCIDENT,
    P.REOPEN_INCIDENT,
    P.VIEW_ANALYTICS,
    P.EXPORT_ANALYTICS,
    P.VIEW_GOVERNANCE,
    P.LOCK_INCIDENT,
    P.UNLOCK_INCIDENT,
    P.OVERRIDE_DECISION,
    P.SLA_OVERRIDE,
    P.TAG_PIR,
    P.TAG_RCA,
    P.ACCEPT_RISK,
    P.VIEW_TEAM_FATIGUE,
    P.VIEW_OWN_FATIGUE,
    P.BULK_OPERATIONS,
    P.VIEW_AUDIT_LOGS,
  ])),

  // ── Incident Response (IR) ─────────────────────────────────────────────
  // Executes containment actions. Deep technical investigation.
  [ROLES.IR]: Object.freeze(new Set([
    P.START_INVESTIGATION,
    P.EXECUTE_CONTAINMENT,
    P.ADD_EVIDENCE,
    P.UPDATE_TRIAGE,
    P.ADJUST_SEVERITY,
    P.CONFIRM_THREAT,
    P.VIEW_OWN_FATIGUE,
  ])),

  // ── Admin ───────────────────────────────────────────────────────────────
  // Full platform access. All permissions.
  [ROLES.ADMIN]: Object.freeze(new Set([
    P.APPROVE_ESCALATION,
    P.REJECT_ESCALATION,
    P.APPROVE_CONTAINMENT,
    P.REJECT_CONTAINMENT,
    P.REQUEST_CONTAINMENT,
    P.EXECUTE_CONTAINMENT,
    P.REASSIGN_INCIDENT,
    P.CLOSE_INCIDENT,
    P.REOPEN_INCIDENT,
    P.SUBMIT_INCIDENT,
    P.START_INVESTIGATION,
    P.ESCALATE_INCIDENT,
    P.ADJUST_SEVERITY,
    P.ADD_EVIDENCE,
    P.UPDATE_TRIAGE,
    P.CONFIRM_THREAT,
    P.MARK_FALSE_POSITIVE,
    P.VIEW_GOVERNANCE,
    P.LOCK_INCIDENT,
    P.UNLOCK_INCIDENT,
    P.OVERRIDE_DECISION,
    P.SLA_OVERRIDE,
    P.TAG_PIR,
    P.TAG_RCA,
    P.ACCEPT_RISK,
    P.VIEW_ANALYTICS,
    P.EXPORT_ANALYTICS,
    P.MANAGE_USERS,
    P.MANAGE_ROLES,
    P.VIEW_AUDIT_LOGS,
    P.VIEW_TEAM_FATIGUE,
    P.VIEW_OWN_FATIGUE,
    P.BULK_OPERATIONS,
  ])),

  // ── Threat Hunter ───────────────────────────────────────────────────────
  // Proactive investigation. Similar to IR but focused on threat hunting.
  [ROLES.THREAT_HUNTER]: Object.freeze(new Set([
    P.START_INVESTIGATION,
    P.ADD_EVIDENCE,
    P.UPDATE_TRIAGE,
    P.ADJUST_SEVERITY,
    P.CONFIRM_THREAT,
    P.ESCALATE_INCIDENT,
    P.VIEW_OWN_FATIGUE,
  ])),
});


// ─── CORE PERMISSION CHECK FUNCTIONS ─────────────────────────────────────────

/**
 * Check whether a canonical role has a specific permission.
 *
 * Safe defaults:
 *   - Unknown role  → false (deny)
 *   - Unknown permission → false (deny)
 *   - null/undefined inputs → false (deny)
 *
 * @param {string} role       - Raw or canonical role string
 * @param {string} permission - Permission key (use PERMISSIONS constants)
 * @returns {boolean} true if the role holds the permission
 *
 * @example
 *   import { hasPermission, PERMISSIONS } from "../security/permissions";
 *   if (hasPermission("soc_manager", PERMISSIONS.APPROVE_ESCALATION)) { ... }
 */
export function hasPermission(role, permission) {
  if (!role || !permission) return false;

  // Normalize the role to handle legacy aliases (e.g., "SOC Manager" → "soc_manager")
  const canonical = normalizeRole(role);
  if (!canonical) return false;

  const permissionSet = ROLE_PERMISSION_MAP[canonical];
  if (!permissionSet) return false;

  // Unknown permission strings silently fail safe (deny)
  return permissionSet.has(permission);
}

/**
 * Check whether a user object has a specific permission.
 *
 * Convenience wrapper around hasPermission() that extracts the role from
 * a user object. Handles the common patterns found across the platform:
 *   - user.role  (most components)
 *   - user.canonicalRole  (normalized contexts)
 *   - Plain string (treated as a role directly)
 *
 * @param {Object|string} user       - User object with .role property, or a role string
 * @param {string}        permission - Permission key (use PERMISSIONS constants)
 * @returns {boolean} true if the user holds the permission
 *
 * @example
 *   import { canUser, PERMISSIONS } from "../security/permissions";
 *
 *   // With user object (from AuthContext)
 *   const { user, role } = useAuth();
 *   if (canUser({ role }, PERMISSIONS.VIEW_ANALYTICS)) { ... }
 *
 *   // With role string directly
 *   if (canUser(role, PERMISSIONS.APPROVE_CONTAINMENT)) { ... }
 */
export function canUser(user, permission) {
  if (!user || !permission) return false;

  // Accept plain string as a role
  if (typeof user === "string") {
    return hasPermission(user, permission);
  }

  // Extract role from user object — try common property names
  const role = user.role || user.canonicalRole || null;
  if (!role) return false;

  return hasPermission(role, permission);
}


// ─── UTILITY FUNCTIONS ───────────────────────────────────────────────────────

/**
 * Get the full set of permissions for a given role.
 * Returns an empty array for unknown roles.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {string[]} Array of permission keys
 *
 * @example
 *   getPermissionsForRole("soc_l1");
 *   // → ["submit_incident", "start_investigation", ...]
 */
export function getPermissionsForRole(role) {
  if (!role) return [];

  const canonical = normalizeRole(role);
  if (!canonical) return [];

  const permissionSet = ROLE_PERMISSION_MAP[canonical];
  if (!permissionSet) return [];

  return Array.from(permissionSet);
}

/**
 * Get all roles that hold a specific permission.
 * Returns an empty array for unknown permissions.
 *
 * @param {string} permission - Permission key
 * @returns {string[]} Array of canonical role strings
 *
 * @example
 *   getRolesWithPermission(PERMISSIONS.APPROVE_ESCALATION);
 *   // → ["soc_manager", "admin"]
 */
export function getRolesWithPermission(permission) {
  if (!permission) return [];

  return Object.entries(ROLE_PERMISSION_MAP)
    .filter(([, permSet]) => permSet.has(permission))
    .map(([role]) => role);
}

/**
 * Validate whether a permission string is a known, defined permission.
 * Useful for runtime assertions and test coverage.
 *
 * @param {string} permission - Permission key to validate
 * @returns {boolean} true if the permission is defined in PERMISSIONS
 */
export function isValidPermission(permission) {
  if (!permission) return false;
  return Object.values(PERMISSIONS).includes(permission);
}

/**
 * Validate whether a role string resolves to a known canonical role.
 *
 * @param {string} role - Role string to validate
 * @returns {boolean} true if the role resolves to a canonical role
 */
export function isValidRole(role) {
  if (!role) return false;
  const canonical = normalizeRole(role);
  return canonical !== null && ROLE_PERMISSION_MAP[canonical] !== undefined;
}

/**
 * Get the full ROLE_PERMISSION_MAP (read-only).
 * Useful for admin dashboards that display the permission matrix.
 *
 * @returns {Object} Frozen map of role → Set<permission>
 */
export function getPermissionMatrix() {
  return ROLE_PERMISSION_MAP;
}
