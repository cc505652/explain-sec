// Role Normalization Utility
// Maps legacy or variant role names to standardized format

export const ROLE_MAP = {
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
  "ir": "ir"
};

/**
 * Normalize role to standard format
 * @param {string} role - Raw role from user object
 * @returns {string} - Normalized role
 */
export function normalizeRole(role) {
  if (!role) return role;
  return ROLE_MAP[role] || role;
}

/**
 * Normalize role array
 * @param {string[]} roles - Array of raw roles
 * @returns {string[]} - Array of normalized roles
 */
export function normalizeRoles(roles) {
  if (!roles || !Array.isArray(roles)) return roles;
  return roles.map(normalizeRole);
}

/**
 * Check if incident is visible to a role
 * Checks visibleTo, assignedTo, and escalatedTo fields
 * @param {object} incident - Incident object
 * @param {string} role - Role to check visibility for
 * @returns {boolean} - True if incident is visible to the role
 */
export function isVisibleToRole(incident, role) {
  const normalizedRole = normalizeRole(role);
  const normalizedAssignedTo = normalizeRole(incident.assignedTo);
  const normalizedEscalatedTo = normalizeRole(incident.escalatedTo);
  const normalizedVisibleTo = incident.visibleTo ? normalizeRoles(incident.visibleTo) : [];
  
  return (
    normalizedVisibleTo.includes(normalizedRole) ||
    normalizedAssignedTo === normalizedRole ||
    normalizedEscalatedTo === normalizedRole
  );
}

/**
 * Check if role is normalized
 * @param {string} role - Role to check
 * @returns {boolean} - True if role is in standard format
 */
export function isNormalizedRole(role) {
  return Object.values(ROLE_MAP).includes(role);
}

/**
 * Get visibleTo array for a specific status and role
 * @param {string} status - Current incident status
 * @param {string} role - Role requesting visibility
 * @returns {string[]} - Array of roles that should see this incident
 */
export function getVisibleToForStatus(status, role) {
  const normalizedRole = normalizeRole(role);
  
  // Define visibility rules based on status
  const statusVisibilityRules = {
    // Initial states - visible to L1 and L2
    open: ["soc_l1", "soc_l2", "soc_manager"],
    assigned: ["soc_l1", "soc_l2", "soc_manager"],
    in_progress: ["soc_l1", "soc_l2", "soc_manager"],
    escalation_requested: ["soc_l1", "soc_l2", "soc_manager"],
    
    // Investigation states - visible to L2 and Manager
    confirmed_threat: ["soc_l2", "soc_manager"],
    false_positive: ["soc_l2", "soc_manager"],
    
    // Escalation states - visible to Manager and IR (once approved)
    escalation_pending: ["soc_l2", "soc_manager"],
    escalation_approved: ["soc_l2", "soc_manager", "ir"],
    escalation_denied: ["soc_l2", "soc_manager"],
    
    // IR investigation states - visible to Manager and IR
    ir_in_progress: ["soc_manager", "ir"],
    
    // Containment workflow states
    containment_pending_approval: ["soc_l2", "soc_manager"],
    containment_in_progress: ["soc_manager", "ir"],
    containment_action_submitted: ["soc_l2", "soc_manager", "ir"],
    containment_approved: ["soc_l2", "soc_manager", "ir"], // Legacy - for execution
    containment_rejected: ["soc_l2", "soc_manager", "ir"],
    containment_review_again: ["soc_l2", "soc_manager", "ir"],
    containment_completed: ["soc_l2", "soc_manager"], // IR removed from workflow
    containment_executed: ["soc_l2", "soc_manager", "ir"],
    
    // L2 investigation state
    investigation_l2: ["soc_l2", "soc_manager"],
    
    // Final states
    resolved: ["soc_l1", "soc_l2", "soc_manager", "ir"],
    reopened: ["soc_l1", "soc_l2", "soc_manager"],
    
    // Legacy states
    containment_pending: ["soc_l2", "soc_manager", "ir"],
    contained: ["soc_l2", "soc_manager", "ir"],
    in_review: ["soc_l1", "soc_l2", "soc_manager"]
  };
  
  return statusVisibilityRules[status] || ["soc_l1", "soc_l2", "soc_manager", "ir"];
}

/**
 * Check if incident should be visible to role based on strict rules
 * @param {object} incident - Incident object
 * @param {string} role - Role to check visibility for
 * @returns {boolean} - True if incident is visible to the role
 */
export function isVisibleToRoleStrict(incident, role) {
  const normalizedRole = normalizeRole(role);
  const status = incident.status || "open";
  const expectedVisibleTo = getVisibleToForStatus(status, normalizedRole);
  
  // Check if role is in the expected visibility array
  return expectedVisibleTo.includes(normalizedRole);
}
