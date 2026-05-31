/**
 * ======================================================================
 * CENTRALIZED GOVERNANCE POLICY REGISTRY — Foundation + Evaluation Layer
 * ======================================================================
 *
 * Phase: FOUNDATION EVOLUTION (additive only — no runtime behavior changed)
 *
 * PURPOSE:
 *   Provides a centralized, immutable registry of governance policies
 *   and their role-based mappings. This becomes the canonical source of
 *   truth for authorization policy definitions that future governance
 *   phases will use to enforce access control.
 *
 * DESIGN:
 *   - Explicit policy constants (not magic strings)
 *   - Explicit role → policy-set mappings (not numeric thresholds)
 *   - Mappings mirror CURRENT platform behavior EXACTLY
 *   - Synchronous, deterministic helpers only
 *   - No Firestore access, no async, no side effects
 *   - Safe defaults: unknown roles/policies → false (deny)
 *
 * RELATIONSHIP TO EXISTING MODULES:
 *   - permissions.js:  Fine-grained operational permissions (action-level)
 *   - policies.js:     Coarse-grained governance policies (capability-level)
 *
 *   All three coexist safely. This module does NOT replace or interfere
 *   with either existing system. It provides a governance-oriented view
 *   of the same canonical roles.
 *
 * BACKWARD COMPATIBILITY:
 *   This module ADDS a new abstraction. It does NOT modify, replace,
 *   or interfere with:
 *     - src/security/permissions.js  (permission engine)
 *     - src/security/auditEngine.js  (audit engine)
 *     - src/utils/normalizeRole.js   (role normalization)
 *     - src/App.jsx                  (routing / ProtectedRoute)
 *     - Any component-level inline role checks
 *
 * FUTURE PHASES:
 *   - Phase 2: Policy evaluation helpers + groupings     ✅ (this file)
 *   - Phase 3: Wire hasPolicy() into ProtectedRoute
 *   - Phase 4: Replace inline role checks in dashboards
 *   - Phase 5: Firestore-backed dynamic policy overrides
 *   - Phase 6: Audit integration for policy check logging
 *
 * ======================================================================
 */

import { normalizeRole } from "../utils/normalizeRole";

// ─── GOVERNANCE POLICY CONSTANTS ─────────────────────────────────────────────
//
// Every governance policy in the platform is declared here as a constant.
// These represent coarse-grained CAPABILITIES, not fine-grained actions.
//
// Naming convention: VERB_NOUN (e.g., MANAGE_USERS, VIEW_GOVERNANCE)
// ─────────────────────────────────────────────────────────────────────────────

export const POLICIES = Object.freeze({

  // ── Incident Access ─────────────────────────────────────────────────────
  /** View incidents (own or assigned) */
  VIEW_INCIDENTS:          "view_incidents",
  /** Submit new incidents */
  SUBMIT_INCIDENTS:        "submit_incidents",

  // ── Investigation ───────────────────────────────────────────────────────
  /** Perform investigation activities (triage, evidence, classification) */
  INVESTIGATE_INCIDENTS:   "investigate_incidents",
  /** Escalate incidents to a higher tier */
  ESCALATE_INCIDENTS:      "escalate_incidents",

  // ── Containment ─────────────────────────────────────────────────────────
  /** Request containment actions */
  REQUEST_CONTAINMENT:     "request_containment",
  /** Execute containment actions (IR-level) */
  EXECUTE_CONTAINMENT:     "execute_containment",
  /** Approve containment actions (Manager/Admin governance) */
  APPROVE_CONTAINMENT:     "approve_containment",

  // ── Incident Governance ─────────────────────────────────────────────────
  /** Reassign incidents to different analysts/teams */
  REASSIGN_INCIDENTS:      "reassign_incidents",
  /** Lock/unlock incidents (governance control) */
  LOCK_INCIDENTS:          "lock_incidents",
  /** Close/resolve incidents */
  CLOSE_INCIDENTS:         "close_incidents",
  /** Reopen resolved incidents */
  REOPEN_INCIDENTS:        "reopen_incidents",

  // ── Escalation Governance ───────────────────────────────────────────────
  /** Approve or reject escalation requests */
  APPROVE_ESCALATIONS:     "approve_escalations",

  // ── Governance & Compliance ─────────────────────────────────────────────
  /** View governance dashboards and compliance data */
  VIEW_GOVERNANCE:         "view_governance",
  /** Override workflow decisions (SLA, triage, etc.) */
  OVERRIDE_DECISIONS:      "override_decisions",

  // ── Analytics & Reporting ───────────────────────────────────────────────
  /** View analytics dashboards */
  VIEW_ANALYTICS:          "view_analytics",
  /** Export analytics data */
  EXPORT_ANALYTICS:        "export_analytics",

  // ── Audit ───────────────────────────────────────────────────────────────
  /** View audit logs */
  VIEW_AUDIT_LOGS:         "view_audit_logs",

  // ── Administration ──────────────────────────────────────────────────────
  /** Manage user accounts (create, update, delete, suspend) */
  MANAGE_USERS:            "manage_users",
  /** Manage role assignments and definitions */
  MANAGE_ROLES:            "manage_roles",

  // ── Team Management ─────────────────────────────────────────────────────
  /** View team-wide fatigue/workload metrics */
  VIEW_TEAM_METRICS:       "view_team_metrics",
  /** Perform bulk operations across incidents */
  BULK_OPERATIONS:         "bulk_operations",
});


// ─── CANONICAL ROLES ─────────────────────────────────────────────────────────
//
// Mirrors the canonical roles from normalizeRole.js.
// Defined here to keep the policy registry self-contained.
// ─────────────────────────────────────────────────────────────────────────────

const ROLES = Object.freeze({
  SOC_L1:         "soc_l1",
  SOC_L2:         "soc_l2",
  SOC_MANAGER:    "soc_manager",
  IR:             "ir",
  ADMIN:          "admin",
  THREAT_HUNTER:  "threat_hunter",
  STUDENT:        "student",
});


// ─── ROLE → POLICY MAPPING ───────────────────────────────────────────────────
//
// Each role explicitly lists its governance policies.
// These mappings mirror CURRENT platform behavior EXACTLY:
//
//   - permissions.js ROLE_PERMISSION_MAP (fine-grained)
//   - App.jsx ProtectedRoute allowedRoles (route access)
//   - Dashboard inline role checks       (component access)
//
// NO capabilities are invented, expanded, or reduced.
// Every entry is traceable to existing runtime behavior.
//
// Higher-privilege roles DO NOT automatically inherit lower-role policies.
// Every role's policy set is explicit and self-contained.
// ─────────────────────────────────────────────────────────────────────────────

const GP = POLICIES; // shorthand for readability

const ROLE_POLICY_MAP = Object.freeze({

  // ── Student ─────────────────────────────────────────────────────────────
  // Can submit incidents and view their own. No operational capabilities.
  // Source: permissions.js → STUDENT has SUBMIT_INCIDENT only
  // Source: App.jsx → student renders SubmitIssue + IssueList
  [ROLES.STUDENT]: Object.freeze(new Set([
    GP.VIEW_INCIDENTS,
    GP.SUBMIT_INCIDENTS,
  ])),

  // ── SOC Analyst L1 ─────────────────────────────────────────────────────
  // Front-line triage. Investigate, classify, escalate to L2.
  // Source: permissions.js → SOC_L1 set
  // Source: App.jsx → renders AnalystDashboard
  [ROLES.SOC_L1]: Object.freeze(new Set([
    GP.VIEW_INCIDENTS,
    GP.SUBMIT_INCIDENTS,
    GP.INVESTIGATE_INCIDENTS,
    GP.ESCALATE_INCIDENTS,
  ])),

  // ── SOC Analyst L2 ─────────────────────────────────────────────────────
  // Deeper investigation. Can request containment.
  // Source: permissions.js → SOC_L2 set (adds ADJUST_SEVERITY, REQUEST_CONTAINMENT)
  // Source: App.jsx → renders AnalystDashboard
  [ROLES.SOC_L2]: Object.freeze(new Set([
    GP.VIEW_INCIDENTS,
    GP.SUBMIT_INCIDENTS,
    GP.INVESTIGATE_INCIDENTS,
    GP.ESCALATE_INCIDENTS,
    GP.REQUEST_CONTAINMENT,
  ])),

  // ── Incident Response (IR) ─────────────────────────────────────────────
  // Executes containment. Deep technical investigation.
  // Source: permissions.js → IR set (has EXECUTE_CONTAINMENT)
  // Source: App.jsx → renders AnalystDashboard
  [ROLES.IR]: Object.freeze(new Set([
    GP.VIEW_INCIDENTS,
    GP.INVESTIGATE_INCIDENTS,
    GP.EXECUTE_CONTAINMENT,
  ])),

  // ── Threat Hunter ───────────────────────────────────────────────────────
  // Proactive investigation. Similar to IR with escalation capability.
  // Source: permissions.js → THREAT_HUNTER set
  // Source: App.jsx → renders AnalystDashboard
  [ROLES.THREAT_HUNTER]: Object.freeze(new Set([
    GP.VIEW_INCIDENTS,
    GP.INVESTIGATE_INCIDENTS,
    GP.ESCALATE_INCIDENTS,
  ])),

  // ── SOC Manager ─────────────────────────────────────────────────────────
  // Operational oversight. Approves escalations, containment, governance.
  // Source: permissions.js → SOC_MANAGER set (full governance suite)
  // Source: App.jsx → ProtectedRoute /soc-manager, /command-console, /analytics
  [ROLES.SOC_MANAGER]: Object.freeze(new Set([
    GP.VIEW_INCIDENTS,
    GP.APPROVE_CONTAINMENT,
    GP.REASSIGN_INCIDENTS,
    GP.LOCK_INCIDENTS,
    GP.CLOSE_INCIDENTS,
    GP.REOPEN_INCIDENTS,
    GP.APPROVE_ESCALATIONS,
    GP.VIEW_GOVERNANCE,
    GP.OVERRIDE_DECISIONS,
    GP.VIEW_ANALYTICS,
    GP.EXPORT_ANALYTICS,
    GP.VIEW_AUDIT_LOGS,
    GP.VIEW_TEAM_METRICS,
    GP.BULK_OPERATIONS,
  ])),

  // ── Admin ───────────────────────────────────────────────────────────────
  // Full platform access. All governance policies.
  // Source: permissions.js → ADMIN set (all permissions)
  // Source: App.jsx → ProtectedRoute /admin, /command-console, /analytics
  [ROLES.ADMIN]: Object.freeze(new Set([
    GP.VIEW_INCIDENTS,
    GP.SUBMIT_INCIDENTS,
    GP.INVESTIGATE_INCIDENTS,
    GP.ESCALATE_INCIDENTS,
    GP.REQUEST_CONTAINMENT,
    GP.EXECUTE_CONTAINMENT,
    GP.APPROVE_CONTAINMENT,
    GP.REASSIGN_INCIDENTS,
    GP.LOCK_INCIDENTS,
    GP.CLOSE_INCIDENTS,
    GP.REOPEN_INCIDENTS,
    GP.APPROVE_ESCALATIONS,
    GP.VIEW_GOVERNANCE,
    GP.OVERRIDE_DECISIONS,
    GP.VIEW_ANALYTICS,
    GP.EXPORT_ANALYTICS,
    GP.VIEW_AUDIT_LOGS,
    GP.MANAGE_USERS,
    GP.MANAGE_ROLES,
    GP.VIEW_TEAM_METRICS,
    GP.BULK_OPERATIONS,
  ])),
});


// ─── VALID POLICY SET (for validation) ───────────────────────────────────────

const VALID_POLICIES = Object.freeze(new Set(Object.values(POLICIES)));


// ─── CORE HELPER FUNCTIONS ───────────────────────────────────────────────────
//
// All helpers are:
//   - Synchronous (no async, no Firestore, no side effects)
//   - Deterministic (same inputs → same outputs, always)
//   - Fail-safe (unknown roles/policies → false/empty, never throws)
//   - Lightweight (Set.has lookups, no heavy computation)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check whether a role has a specific governance policy.
 *
 * Safe defaults:
 *   - Unknown role     → false (deny)
 *   - Unknown policy   → false (deny)
 *   - null/undefined   → false (deny)
 *
 * @param {string} role   - Raw or canonical role string
 * @param {string} policy - Policy key (use POLICIES constants)
 * @returns {boolean} true if the role holds the policy
 *
 * @example
 *   import { hasPolicy, POLICIES } from "../security/policies";
 *   if (hasPolicy("admin", POLICIES.MANAGE_USERS)) { ... }
 */
export function hasPolicy(role, policy) {
  if (!role || !policy) return false;

  const canonical = normalizeRole(role);
  if (!canonical) return false;

  const policySet = ROLE_POLICY_MAP[canonical];
  if (!policySet) return false;

  return policySet.has(policy);
}

/**
 * Get the full set of governance policies for a given role.
 * Returns an empty array for unknown roles.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {string[]} Array of policy keys
 *
 * @example
 *   getPoliciesForRole("soc_manager");
 *   // → ["view_incidents", "approve_containment", ...]
 */
export function getPoliciesForRole(role) {
  if (!role) return [];

  const canonical = normalizeRole(role);
  if (!canonical) return [];

  const policySet = ROLE_POLICY_MAP[canonical];
  if (!policySet) return [];

  return Array.from(policySet);
}

/**
 * Validate whether a policy string is a known, defined governance policy.
 *
 * @param {string} policy - Policy key to validate
 * @returns {boolean} true if the policy is defined in POLICIES
 *
 * @example
 *   validatePolicy("manage_users");  // → true
 *   validatePolicy("fly_to_moon");   // → false
 */
export function validatePolicy(policy) {
  if (!policy) return false;
  return VALID_POLICIES.has(policy);
}


// ─── ADDITIONAL UTILITY FUNCTIONS ────────────────────────────────────────────

/**
 * Get all roles that hold a specific governance policy.
 * Returns an empty array for unknown policies.
 *
 * @param {string} policy - Policy key
 * @returns {string[]} Array of canonical role strings
 *
 * @example
 *   getRolesWithPolicy(POLICIES.MANAGE_USERS);
 *   // → ["admin"]
 */
export function getRolesWithPolicy(policy) {
  if (!policy) return [];

  return Object.entries(ROLE_POLICY_MAP)
    .filter(([, policySet]) => policySet.has(policy))
    .map(([role]) => role);
}

/**
 * Get the full ROLE_POLICY_MAP (read-only).
 * Useful for admin dashboards that display the policy matrix.
 *
 * @returns {Object} Frozen map of role → Set<policy>
 */
export function getPolicyMatrix() {
  return ROLE_POLICY_MAP;
}


// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2 — POLICY EVALUATION LAYER
// ═══════════════════════════════════════════════════════════════════════════════
//
// Added: Foundation Evolution phase
//
// Everything below is ADDITIVE. No existing function or constant above
// was modified. All helpers are synchronous, deterministic, and fail-safe.
//
// Sections:
//   1. Policy Grouping Constants
//   2. Domain-Specific Evaluation Helpers
//   3. Compatibility Bridges
//   4. Diagnostics Helpers
// ═══════════════════════════════════════════════════════════════════════════════


// ─── 1. POLICY GROUPING CONSTANTS ────────────────────────────────────────────
//
// Frozen sets of related policies grouped by governance domain.
// Useful for bulk policy checks, UI rendering of policy groups,
// and future migration of domain-level access gates.
//
// These groupings do NOT define authorization — they are organizational only.
// ─────────────────────────────────────────────────────────────────────────────

/** Policies related to governance oversight and compliance */
export const GOVERNANCE_POLICIES = Object.freeze([
  POLICIES.VIEW_GOVERNANCE,
  POLICIES.OVERRIDE_DECISIONS,
  POLICIES.LOCK_INCIDENTS,
  POLICIES.REOPEN_INCIDENTS,
  POLICIES.VIEW_AUDIT_LOGS,
]);

/** Policies related to incident lifecycle management */
export const INCIDENT_POLICIES = Object.freeze([
  POLICIES.VIEW_INCIDENTS,
  POLICIES.SUBMIT_INCIDENTS,
  POLICIES.INVESTIGATE_INCIDENTS,
  POLICIES.ESCALATE_INCIDENTS,
  POLICIES.REASSIGN_INCIDENTS,
  POLICIES.CLOSE_INCIDENTS,
  POLICIES.REOPEN_INCIDENTS,
]);

/** Policies related to containment operations */
export const CONTAINMENT_POLICIES = Object.freeze([
  POLICIES.REQUEST_CONTAINMENT,
  POLICIES.EXECUTE_CONTAINMENT,
  POLICIES.APPROVE_CONTAINMENT,
]);

/** Policies related to analytics and reporting */
export const ANALYTICS_POLICIES = Object.freeze([
  POLICIES.VIEW_ANALYTICS,
  POLICIES.EXPORT_ANALYTICS,
]);

/** Policies related to platform administration */
export const ADMIN_POLICIES = Object.freeze([
  POLICIES.MANAGE_USERS,
  POLICIES.MANAGE_ROLES,
  POLICIES.VIEW_AUDIT_LOGS,
  POLICIES.VIEW_TEAM_METRICS,
  POLICIES.BULK_OPERATIONS,
]);

/** Policies related to escalation governance */
export const ESCALATION_POLICIES = Object.freeze([
  POLICIES.ESCALATE_INCIDENTS,
  POLICIES.APPROVE_ESCALATIONS,
]);


// ─── 2. DOMAIN-SPECIFIC EVALUATION HELPERS ───────────────────────────────────
//
// Convenience functions that wrap hasPolicy() for common domain-level checks.
// These mirror the governance capabilities the platform currently uses.
//
// All helpers:
//   - Synchronous (no async, no Firestore, no side effects)
//   - Deterministic (same inputs → same outputs)
//   - Fail-safe (unknown/null roles → false)
//   - Delegate to hasPolicy() internally
//
// These DO NOT enforce authorization. They are evaluation-only helpers
// that future migration phases will wire into components.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Can the role access governance dashboards and compliance features?
 * Maps to: soc_manager, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canAccessGovernance(role) {
  return hasPolicy(role, POLICIES.VIEW_GOVERNANCE);
}

/**
 * Can the role manage user accounts (create, update, delete, suspend)?
 * Maps to: admin only
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canManageUsers(role) {
  return hasPolicy(role, POLICIES.MANAGE_USERS);
}

/**
 * Can the role view analytics dashboards?
 * Maps to: soc_manager, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canViewAnalytics(role) {
  return hasPolicy(role, POLICIES.VIEW_ANALYTICS);
}

/**
 * Can the role manage incidents (reassign, lock, close, reopen)?
 * Maps to: soc_manager, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canManageIncidents(role) {
  return hasPolicy(role, POLICIES.REASSIGN_INCIDENTS)
      && hasPolicy(role, POLICIES.CLOSE_INCIDENTS);
}

/**
 * Can the role execute containment actions?
 * Maps to: ir, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canExecuteContainment(role) {
  return hasPolicy(role, POLICIES.EXECUTE_CONTAINMENT);
}

/**
 * Can the role approve containment actions?
 * Maps to: soc_manager, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canApproveContainment(role) {
  return hasPolicy(role, POLICIES.APPROVE_CONTAINMENT);
}

/**
 * Can the role view audit logs?
 * Maps to: soc_manager, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canViewAuditLogs(role) {
  return hasPolicy(role, POLICIES.VIEW_AUDIT_LOGS);
}

/**
 * Can the role manage role assignments and definitions?
 * Maps to: admin only
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canManageRoles(role) {
  return hasPolicy(role, POLICIES.MANAGE_ROLES);
}

/**
 * Can the role approve or reject escalation requests?
 * Maps to: soc_manager, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canApproveEscalations(role) {
  return hasPolicy(role, POLICIES.APPROVE_ESCALATIONS);
}

/**
 * Can the role perform investigation activities?
 * Maps to: soc_l1, soc_l2, ir, threat_hunter, admin
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function canInvestigate(role) {
  return hasPolicy(role, POLICIES.INVESTIGATE_INCIDENTS);
}


// ─── 3. COMPATIBILITY BRIDGES ────────────────────────────────────────────────
//
// Bridge functions that map legacy-style role checks to hasPolicy() internally.
// These preserve the naming patterns found across the platform while routing
// through the centralized policy registry.
//
// Future migration phases will replace inline role checks with these bridges
// as an intermediate step before full policy enforcement.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check if a role has governance-level access.
 * Compatibility bridge for inline `role === "soc_manager" || role === "admin"` checks.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function roleHasGovernanceAccess(role) {
  return hasPolicy(role, POLICIES.VIEW_GOVERNANCE);
}

/**
 * Check if a role has admin-level access (user/role management).
 * Compatibility bridge for inline `role === "admin"` checks.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function roleHasAdminAccess(role) {
  return hasPolicy(role, POLICIES.MANAGE_USERS)
      && hasPolicy(role, POLICIES.MANAGE_ROLES);
}

/**
 * Check if a role has analytics access.
 * Compatibility bridge for inline `role === "soc_manager" || role === "admin"` checks.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function roleHasAnalyticsAccess(role) {
  return hasPolicy(role, POLICIES.VIEW_ANALYTICS);
}

/**
 * Check if a role has incident management access (reassign, close, lock).
 * Compatibility bridge for manager-level inline role checks.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function roleHasIncidentManagement(role) {
  return hasPolicy(role, POLICIES.REASSIGN_INCIDENTS)
      && hasPolicy(role, POLICIES.CLOSE_INCIDENTS);
}

/**
 * Check if a role has containment execution capability.
 * Compatibility bridge for IR-level inline role checks.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {boolean}
 */
export function roleHasContainmentExecution(role) {
  return hasPolicy(role, POLICIES.EXECUTE_CONTAINMENT);
}


// ─── 4. DIAGNOSTICS HELPERS ─────────────────────────────────────────────────
//
// Lightweight diagnostic utilities for policy integrity checks.
// Useful for admin dashboards, test assertions, and migration validation.
//
// All diagnostics are:
//   - Synchronous (no async, no Firestore)
//   - Deterministic (same inputs → same outputs)
//   - Side-effect free (no mutations, no writes)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Get the policies a role is MISSING from a required set.
 * Returns an empty array if the role has all required policies.
 *
 * @param {string}   role             - Raw or canonical role string
 * @param {string[]} requiredPolicies - Array of policy keys to check
 * @returns {string[]} Array of missing policy keys
 *
 * @example
 *   getMissingPolicies("soc_l1", [POLICIES.VIEW_INCIDENTS, POLICIES.MANAGE_USERS]);
 *   // → ["manage_users"]
 */
export function getMissingPolicies(role, requiredPolicies) {
  if (!role || !Array.isArray(requiredPolicies)) return [];

  return requiredPolicies.filter((policy) => !hasPolicy(role, policy));
}

/**
 * Detect invalid policy strings in a given array.
 * Returns policy strings that are NOT defined in the POLICIES constants.
 *
 * @param {string[]} policies - Array of policy strings to validate
 * @returns {string[]} Array of invalid/unknown policy strings
 *
 * @example
 *   detectInvalidPolicies(["manage_users", "fly_to_moon", "view_incidents"]);
 *   // → ["fly_to_moon"]
 */
export function detectInvalidPolicies(policies) {
  if (!Array.isArray(policies)) return [];

  return policies.filter((policy) => !validatePolicy(policy));
}

/**
 * Check if a role satisfies ALL policies in a required set.
 * Useful for multi-policy gates (e.g., "must have both VIEW_ANALYTICS and EXPORT_ANALYTICS").
 *
 * @param {string}   role             - Raw or canonical role string
 * @param {string[]} requiredPolicies - Array of policy keys (ALL must be satisfied)
 * @returns {boolean} true if the role has every required policy
 *
 * @example
 *   hasAllPolicies("admin", [POLICIES.MANAGE_USERS, POLICIES.MANAGE_ROLES]);
 *   // → true
 *   hasAllPolicies("soc_l1", [POLICIES.MANAGE_USERS, POLICIES.MANAGE_ROLES]);
 *   // → false
 */
export function hasAllPolicies(role, requiredPolicies) {
  if (!role || !Array.isArray(requiredPolicies) || requiredPolicies.length === 0) return false;

  return requiredPolicies.every((policy) => hasPolicy(role, policy));
}

/**
 * Check if a role satisfies ANY policy in a given set.
 * Useful for OR-style gates (e.g., "can access if has VIEW_ANALYTICS OR VIEW_GOVERNANCE").
 *
 * @param {string}   role     - Raw or canonical role string
 * @param {string[]} policies - Array of policy keys (ANY must be satisfied)
 * @returns {boolean} true if the role has at least one of the policies
 *
 * @example
 *   hasAnyPolicy("soc_manager", [POLICIES.MANAGE_USERS, POLICIES.VIEW_ANALYTICS]);
 *   // → true (has VIEW_ANALYTICS)
 */
export function hasAnyPolicy(role, policies) {
  if (!role || !Array.isArray(policies) || policies.length === 0) return false;

  return policies.some((policy) => hasPolicy(role, policy));
}

/**
 * Generate a diagnostic report for a role's policy coverage.
 * Returns an object describing the role's policies, missing policies
 * relative to all defined policies, and which policy groups are covered.
 *
 * @param {string} role - Raw or canonical role string
 * @returns {{ role: string, policies: string[], totalDefined: number, coverage: number, missingPolicies: string[], groupCoverage: Object }}
 *
 * @example
 *   getPolicyReport("soc_l1");
 *   // → { role: "soc_l1", policies: [...], totalDefined: 21, coverage: 0.19, ... }
 */
export function getPolicyReport(role) {
  const canonical = normalizeRole(role);
  const rolePolicies = getPoliciesForRole(role);
  const allPolicies = Object.values(POLICIES);
  const missing = getMissingPolicies(role, allPolicies);

  return {
    role: canonical || role || "unknown",
    policies: rolePolicies,
    totalDefined: allPolicies.length,
    coverage: allPolicies.length > 0
      ? Math.round((rolePolicies.length / allPolicies.length) * 100) / 100
      : 0,
    missingPolicies: missing,
    groupCoverage: {
      governance:   hasAnyPolicy(role, GOVERNANCE_POLICIES),
      incidents:    hasAnyPolicy(role, INCIDENT_POLICIES),
      containment:  hasAnyPolicy(role, CONTAINMENT_POLICIES),
      analytics:    hasAnyPolicy(role, ANALYTICS_POLICIES),
      admin:        hasAnyPolicy(role, ADMIN_POLICIES),
      escalation:   hasAnyPolicy(role, ESCALATION_POLICIES),
    },
  };
}
