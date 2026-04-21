/**
 * ======================================================================
 * CAMPUS SOC — ROLE PERMISSION ENGINE (Phase 9 — Batch D)
 * ======================================================================
 *
 * Centralized, granular RBAC engine. Replaces the scattered ROLE_PERMISSIONS
 * constants duplicated across multiple dashboard files.
 *
 * Single import point for all role-based access decisions.
 * ======================================================================
 */

/* ---------- ROLE HIERARCHY ---------- */

export const ROLE_HIERARCHY = Object.freeze({
  admin:          { level: 100, label: "Administrator",        icon: "👑" },
  soc_manager:    { level: 80,  label: "SOC Manager",          icon: "🎖️" },
  ir:             { level: 60,  label: "Incident Responder",   icon: "🛡️" },
  threat_hunter:  { level: 60,  label: "Threat Hunter",        icon: "🔍" },
  soc_l2:         { level: 40,  label: "SOC Analyst L2",       icon: "🔬" },
  soc_l1:         { level: 30,  label: "SOC Analyst L1",       icon: "📡" },
  analyst:        { level: 20,  label: "Analyst",              icon: "📊" },
  student:        { level: 10,  label: "Student",              icon: "🎓" },
});

/* ---------- PERMISSION MATRIX ---------- */

/**
 * Granular permissions per role.
 * Each key is a permission name, value is the minimum role level required.
 */
const PERMISSION_MATRIX = Object.freeze({
  // Incident Lifecycle
  submit_incident:        10,   // students+
  view_own_incidents:     10,
  view_all_incidents:     20,
  start_incident:         30,
  resolve_incident:       30,
  assign_incident:        40,
  escalate_incident:      30,
  
  // Investigation
  add_evidence:           30,
  update_tags:            30,
  update_triage:          30,
  adjust_severity:        30,
  request_containment:    40,
  perform_containment:    60,
  
  // Governance
  lock_incident:          80,
  unlock_incident:        80,
  override_decision:      80,
  sla_override:           80,
  transfer_ownership:     80,
  accept_risk:            80,
  tag_rca:                80,
  tag_pir:                80,
  reopen_incident:        80,
  convert_threat_hunt:    80,
  reject_containment:     80,
  
  // Approvals
  request_approval:       30,
  process_approval:       80,
  
  // Bulk Operations
  bulk_operations:        80,
  
  // Analytics
  view_analytics_basic:   20,
  view_analytics_full:    80,
  export_analytics:       80,
  
  // Administration
  manage_users:           100,
  manage_roles:           100,
  manage_policies:        100,
  view_audit_logs:        80,
  
  // Investigation Panel
  open_investigation:     30,
  add_handoff_notes:      30,
  
  // Fatigue Monitoring
  view_team_fatigue:      80,
  view_own_fatigue:       30,
});

/* ---------- CORE FUNCTIONS ---------- */

/**
 * Check if a role has a specific permission.
 *
 * @param {string} role - user role
 * @param {string} permission - permission key
 * @returns {boolean}
 */
export function hasPermission(role, permission) {
  const roleData = ROLE_HIERARCHY[role];
  if (!roleData) return false;

  const requiredLevel = PERMISSION_MATRIX[permission];
  if (requiredLevel === undefined) {
    console.warn(`[RBAC] Unknown permission: ${permission}`);
    return false;
  }

  return roleData.level >= requiredLevel;
}

/**
 * Get all permissions for a role.
 *
 * @param {string} role
 * @returns {string[]}
 */
export function getPermissions(role) {
  const roleData = ROLE_HIERARCHY[role];
  if (!roleData) return [];

  return Object.entries(PERMISSION_MATRIX)
    .filter(([, level]) => roleData.level >= level)
    .map(([perm]) => perm);
}

/**
 * Get role display info.
 *
 * @param {string} role
 * @returns {{ label: string, icon: string, level: number }}
 */
export function getRoleInfo(role) {
  return ROLE_HIERARCHY[role] || { label: role, icon: "❓", level: 0 };
}

/**
 * Check if roleA outranks roleB.
 */
export function outranks(roleA, roleB) {
  const a = ROLE_HIERARCHY[roleA]?.level || 0;
  const b = ROLE_HIERARCHY[roleB]?.level || 0;
  return a > b;
}

/**
 * Get all roles that can perform a specific action.
 */
export function getRolesForPermission(permission) {
  const requiredLevel = PERMISSION_MATRIX[permission];
  if (requiredLevel === undefined) return [];

  return Object.entries(ROLE_HIERARCHY)
    .filter(([, data]) => data.level >= requiredLevel)
    .map(([role]) => role);
}

/**
 * Get the access level for analytics (used by AnalyticsPanel).
 */
export function getAnalyticsAccessLevel(role) {
  if (hasPermission(role, "view_analytics_full")) return "full";
  if (hasPermission(role, "view_analytics_basic")) return "limited";
  return "none";
}

/* ---------- PERMISSION GROUPS (for UI display) ---------- */

export const PERMISSION_GROUPS = Object.freeze({
  "Incident Lifecycle": [
    "submit_incident", "view_own_incidents", "view_all_incidents",
    "start_incident", "resolve_incident", "assign_incident", "escalate_incident",
  ],
  "Investigation": [
    "add_evidence", "update_tags", "update_triage",
    "adjust_severity", "request_containment", "perform_containment",
  ],
  "Governance": [
    "lock_incident", "unlock_incident", "override_decision",
    "sla_override", "transfer_ownership", "accept_risk",
    "tag_rca", "tag_pir", "reopen_incident",
  ],
  "Analytics & Reports": [
    "view_analytics_basic", "view_analytics_full", "export_analytics",
  ],
  "Administration": [
    "manage_users", "manage_roles", "manage_policies", "view_audit_logs",
  ],
});
