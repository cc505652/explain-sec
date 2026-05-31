/**
 * ======================================================================
 * GOVERNANCE DIAGNOSTICS ENGINE
 * ======================================================================
 *
 * Phase: DIAGNOSTICS (additive only — no runtime behavior modified)
 *
 * PURPOSE:
 *   Provides centralized governance validation and integrity checking
 *   utilities. These diagnostics allow the platform to self-validate
 *   its governance configuration and detect inconsistencies between
 *   the permission engine and the policy registry.
 *
 * DESIGN:
 *   - All functions are synchronous, deterministic, and side-effect free
 *   - Zero Firestore access, zero async behavior, zero network calls
 *   - Uses only in-memory data from permissions.js and policies.js
 *   - Dev-only console output is guarded by NODE_ENV check
 *   - Never runs during renders — must be called explicitly
 *
 * RELATIONSHIP TO EXISTING MODULES:
 *   - permissions.js:  Source for fine-grained permission data
 *   - policies.js:     Source for coarse-grained policy data
 *   - This module:     Cross-validates both against each other
 *
 * BACKWARD COMPATIBILITY:
 *   This module is fully isolated. It does NOT modify, replace, or
 *   interfere with any existing module. It only reads exported data
 *   from permissions.js and policies.js via their public APIs.
 *
 * FUTURE PHASES:
 *   - Phase 2: Wire diagnostics into admin dashboard governance tab
 *   - Phase 3: Automated CI/CD governance integrity checks
 *   - Phase 4: Audit log integration for governance drift detection
 *
 * ======================================================================
 */

import {
  POLICIES,
  hasPolicy,
  getPoliciesForRole,
  validatePolicy,
  getRolesWithPolicy,
  getPolicyMatrix,
  GOVERNANCE_POLICIES,
  INCIDENT_POLICIES,
  CONTAINMENT_POLICIES,
  ANALYTICS_POLICIES,
  ADMIN_POLICIES,
  ESCALATION_POLICIES,
} from "./policies";

import {
  PERMISSIONS,
  hasPermission,
  getPermissionsForRole,
  isValidPermission,
  isValidRole,
  getPermissionMatrix,
  ROLES,
} from "./permissions";


// ─── CANONICAL ROLE LIST ─────────────────────────────────────────────────────
//
// Single source of truth for all roles the diagnostics engine validates against.
// ─────────────────────────────────────────────────────────────────────────────

const ALL_CANONICAL_ROLES = Object.freeze([
  "soc_l1",
  "soc_l2",
  "soc_manager",
  "ir",
  "admin",
  "threat_hunter",
  "student",
]);


// ─── ALL DEFINED POLICIES ────────────────────────────────────────────────────

const ALL_DEFINED_POLICIES = Object.freeze(Object.values(POLICIES));


// ─── ALL DEFINED PERMISSIONS ─────────────────────────────────────────────────

const ALL_DEFINED_PERMISSIONS = Object.freeze(Object.values(PERMISSIONS));


// ─── POLICY GROUPS (for group coverage analysis) ─────────────────────────────

const POLICY_GROUPS = Object.freeze({
  governance:  GOVERNANCE_POLICIES,
  incidents:   INCIDENT_POLICIES,
  containment: CONTAINMENT_POLICIES,
  analytics:   ANALYTICS_POLICIES,
  admin:       ADMIN_POLICIES,
  escalation:  ESCALATION_POLICIES,
});


// ═══════════════════════════════════════════════════════════════════════════════
// 1. ORPHAN & INTEGRITY DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detect orphan policies — policies that are defined in POLICIES constants
 * but are NOT assigned to ANY role in the ROLE_POLICY_MAP.
 *
 * Orphan policies may indicate:
 *   - A policy was defined but never mapped to a role
 *   - A role mapping was accidentally removed
 *   - A new policy was added without updating role assignments
 *
 * @returns {{ orphanPolicies: string[], count: number }}
 *
 * @example
 *   const result = detectOrphanPolicies();
 *   // → { orphanPolicies: [], count: 0 } (healthy)
 */
export function detectOrphanPolicies() {
  const assignedPolicies = new Set();

  for (const role of ALL_CANONICAL_ROLES) {
    const rolePolicies = getPoliciesForRole(role);
    for (const policy of rolePolicies) {
      assignedPolicies.add(policy);
    }
  }

  const orphanPolicies = ALL_DEFINED_POLICIES.filter(
    (policy) => !assignedPolicies.has(policy)
  );

  return {
    orphanPolicies,
    count: orphanPolicies.length,
  };
}


/**
 * Detect invalid role references in the ROLE_POLICY_MAP — roles that
 * exist in the policy map but are NOT recognized canonical roles.
 *
 * @returns {{ invalidRoles: string[], count: number }}
 *
 * @example
 *   const result = detectInvalidRoleMappings();
 *   // → { invalidRoles: [], count: 0 } (healthy)
 */
export function detectInvalidRoleMappings() {
  const policyMatrix = getPolicyMatrix();
  const invalidRoles = Object.keys(policyMatrix).filter(
    (role) => !ALL_CANONICAL_ROLES.includes(role)
  );

  return {
    invalidRoles,
    count: invalidRoles.length,
  };
}


/**
 * Detect duplicate policy definitions — policy values that appear
 * more than once in the POLICIES constant object (different keys,
 * same string value).
 *
 * @returns {{ duplicates: Array<{ value: string, keys: string[] }>, count: number }}
 *
 * @example
 *   const result = detectDuplicatePolicies();
 *   // → { duplicates: [], count: 0 } (healthy)
 */
export function detectDuplicatePolicies() {
  const valueToKeys = {};

  for (const [key, value] of Object.entries(POLICIES)) {
    if (!valueToKeys[value]) {
      valueToKeys[value] = [];
    }
    valueToKeys[value].push(key);
  }

  const duplicates = Object.entries(valueToKeys)
    .filter(([, keys]) => keys.length > 1)
    .map(([value, keys]) => ({ value, keys }));

  return {
    duplicates,
    count: duplicates.length,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 2. ROLE-POLICY ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get all roles that are MISSING a specific policy.
 * The inverse of getRolesWithPolicy() — useful for gap analysis.
 *
 * @param {string} policy - Policy key
 * @returns {string[]} Array of canonical role strings that lack the policy
 *
 * @example
 *   getRolesMissingPolicy(POLICIES.VIEW_GOVERNANCE);
 *   // → ["soc_l1", "soc_l2", "ir", "threat_hunter", "student"]
 */
export function getRolesMissingPolicy(policy) {
  if (!policy) return [];

  return ALL_CANONICAL_ROLES.filter((role) => !hasPolicy(role, policy));
}


/**
 * Validate the integrity of all role-policy mappings.
 *
 * Checks:
 *   1. Every role in the policy map is a valid canonical role
 *   2. Every policy assigned to a role is a valid defined policy
 *   3. Every defined policy is assigned to at least one role
 *   4. No duplicate policy values exist
 *   5. Admin has a superset of all policies (completeness check)
 *
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 *
 * @example
 *   const result = validateRolePolicyIntegrity();
 *   if (!result.valid) console.warn("Governance issues:", result.errors);
 */
export function validateRolePolicyIntegrity() {
  const errors = [];
  const warnings = [];

  // Check 1: All roles in policy map are valid
  const invalidRoles = detectInvalidRoleMappings();
  if (invalidRoles.count > 0) {
    errors.push(
      `Invalid roles in ROLE_POLICY_MAP: ${invalidRoles.invalidRoles.join(", ")}`
    );
  }

  // Check 2: All assigned policies are valid defined policies
  for (const role of ALL_CANONICAL_ROLES) {
    const rolePolicies = getPoliciesForRole(role);
    for (const policy of rolePolicies) {
      if (!validatePolicy(policy)) {
        errors.push(
          `Role "${role}" has invalid policy: "${policy}"`
        );
      }
    }
  }

  // Check 3: All defined policies are assigned to at least one role
  const orphans = detectOrphanPolicies();
  if (orphans.count > 0) {
    warnings.push(
      `Orphan policies (not assigned to any role): ${orphans.orphanPolicies.join(", ")}`
    );
  }

  // Check 4: No duplicate policy values
  const duplicates = detectDuplicatePolicies();
  if (duplicates.count > 0) {
    errors.push(
      `Duplicate policy values: ${duplicates.duplicates.map((d) => `"${d.value}" (keys: ${d.keys.join(", ")})`).join("; ")}`
    );
  }

  // Check 5: Admin should have all policies (completeness check)
  const adminPolicies = getPoliciesForRole("admin");
  const missingFromAdmin = ALL_DEFINED_POLICIES.filter(
    (p) => !adminPolicies.includes(p)
  );
  if (missingFromAdmin.length > 0) {
    warnings.push(
      `Admin role is missing policies: ${missingFromAdmin.join(", ")}`
    );
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 3. CROSS-MODULE CONSISTENCY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detect governance inconsistencies between the permission engine
 * (permissions.js) and the policy registry (policies.js).
 *
 * Checks:
 *   1. Both modules define the same canonical roles
 *   2. Permission-to-policy alignment for key capabilities
 *   3. Roles with MANAGE_USERS permission also have MANAGE_USERS policy
 *   4. Roles with VIEW_ANALYTICS permission also have VIEW_ANALYTICS policy
 *   5. Roles with VIEW_AUDIT_LOGS permission also have VIEW_AUDIT_LOGS policy
 *
 * @returns {{ consistent: boolean, mismatches: string[], details: Object }}
 */
export function detectGovernanceInconsistencies() {
  const mismatches = [];

  // Check 1: Both modules define the same roles
  const permissionMatrix = getPermissionMatrix();
  const policyMatrix = getPolicyMatrix();

  const permRoles = new Set(Object.keys(permissionMatrix));
  const policyRoles = new Set(Object.keys(policyMatrix));

  for (const role of permRoles) {
    if (!policyRoles.has(role)) {
      mismatches.push(
        `Role "${role}" exists in permissions.js but not in policies.js`
      );
    }
  }
  for (const role of policyRoles) {
    if (!permRoles.has(role)) {
      mismatches.push(
        `Role "${role}" exists in policies.js but not in permissions.js`
      );
    }
  }

  // Check 2-5: Key permission↔policy alignment
  const alignmentChecks = [
    {
      permission: PERMISSIONS.MANAGE_USERS,
      policy: POLICIES.MANAGE_USERS,
      label: "MANAGE_USERS",
    },
    {
      permission: PERMISSIONS.MANAGE_ROLES,
      policy: POLICIES.MANAGE_ROLES,
      label: "MANAGE_ROLES",
    },
    {
      permission: PERMISSIONS.VIEW_ANALYTICS,
      policy: POLICIES.VIEW_ANALYTICS,
      label: "VIEW_ANALYTICS",
    },
    {
      permission: PERMISSIONS.VIEW_AUDIT_LOGS,
      policy: POLICIES.VIEW_AUDIT_LOGS,
      label: "VIEW_AUDIT_LOGS",
    },
    {
      permission: PERMISSIONS.VIEW_GOVERNANCE,
      policy: POLICIES.VIEW_GOVERNANCE,
      label: "VIEW_GOVERNANCE",
    },
    {
      permission: PERMISSIONS.APPROVE_CONTAINMENT,
      policy: POLICIES.APPROVE_CONTAINMENT,
      label: "APPROVE_CONTAINMENT",
    },
    {
      permission: PERMISSIONS.EXECUTE_CONTAINMENT,
      policy: POLICIES.EXECUTE_CONTAINMENT,
      label: "EXECUTE_CONTAINMENT",
    },
  ];

  const details = {};

  for (const check of alignmentChecks) {
    const rolesWithPerm = ALL_CANONICAL_ROLES.filter((r) =>
      hasPermission(r, check.permission)
    );
    const rolesWithPolicy = ALL_CANONICAL_ROLES.filter((r) =>
      hasPolicy(r, check.policy)
    );

    const permSet = new Set(rolesWithPerm);
    const policySet = new Set(rolesWithPolicy);

    const inPermNotPolicy = rolesWithPerm.filter((r) => !policySet.has(r));
    const inPolicyNotPerm = rolesWithPolicy.filter((r) => !permSet.has(r));

    if (inPermNotPolicy.length > 0 || inPolicyNotPerm.length > 0) {
      mismatches.push(
        `${check.label}: permission↔policy mismatch — ` +
          (inPermNotPolicy.length > 0
            ? `has permission but no policy: [${inPermNotPolicy.join(", ")}]`
            : "") +
          (inPolicyNotPerm.length > 0
            ? `has policy but no permission: [${inPolicyNotPerm.join(", ")}]`
            : "")
      );
    }

    details[check.label] = {
      aligned: inPermNotPolicy.length === 0 && inPolicyNotPerm.length === 0,
      rolesWithPermission: rolesWithPerm,
      rolesWithPolicy: rolesWithPolicy,
      inPermNotPolicy,
      inPolicyNotPerm,
    };
  }

  return {
    consistent: mismatches.length === 0,
    mismatches,
    details,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 4. COMPREHENSIVE GOVERNANCE REPORT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate a comprehensive governance integrity report.
 *
 * Aggregates all diagnostics into a single structured report suitable
 * for admin dashboards, CI/CD checks, or developer inspection.
 *
 * @returns {Object} Full governance report with:
 *   - timestamp
 *   - summary (pass/fail counts)
 *   - rolePolicyIntegrity
 *   - orphanPolicies
 *   - invalidRoleMappings
 *   - duplicatePolicies
 *   - crossModuleConsistency
 *   - roleCoverage (per-role policy/permission counts)
 *   - groupCoverage (per-group policy assignment analysis)
 *
 * @example
 *   const report = generateGovernanceReport();
 *   console.table(report.roleCoverage);
 */
export function generateGovernanceReport() {
  // Run all diagnostics
  const integrity = validateRolePolicyIntegrity();
  const orphans = detectOrphanPolicies();
  const invalidRoles = detectInvalidRoleMappings();
  const duplicates = detectDuplicatePolicies();
  const consistency = detectGovernanceInconsistencies();

  // Per-role coverage analysis
  const roleCoverage = ALL_CANONICAL_ROLES.map((role) => {
    const policies = getPoliciesForRole(role);
    const permissions = getPermissionsForRole(role);

    return {
      role,
      policyCount: policies.length,
      permissionCount: permissions.length,
      policyCoverage:
        ALL_DEFINED_POLICIES.length > 0
          ? Math.round((policies.length / ALL_DEFINED_POLICIES.length) * 100)
          : 0,
      permissionCoverage:
        ALL_DEFINED_PERMISSIONS.length > 0
          ? Math.round(
              (permissions.length / ALL_DEFINED_PERMISSIONS.length) * 100
            )
          : 0,
    };
  });

  // Policy group coverage analysis
  const groupCoverage = {};
  for (const [groupName, groupPolicies] of Object.entries(POLICY_GROUPS)) {
    groupCoverage[groupName] = {
      totalPolicies: groupPolicies.length,
      rolesWithFullCoverage: ALL_CANONICAL_ROLES.filter((role) =>
        groupPolicies.every((p) => hasPolicy(role, p))
      ),
      rolesWithPartialCoverage: ALL_CANONICAL_ROLES.filter((role) => {
        const has = groupPolicies.filter((p) => hasPolicy(role, p));
        return has.length > 0 && has.length < groupPolicies.length;
      }),
      rolesWithNoCoverage: ALL_CANONICAL_ROLES.filter((role) =>
        groupPolicies.every((p) => !hasPolicy(role, p))
      ),
    };
  }

  // Summary
  const errorCount = integrity.errors.length + (consistency.consistent ? 0 : consistency.mismatches.length);
  const warningCount = integrity.warnings.length + orphans.count + duplicates.count;

  return {
    timestamp: new Date().toISOString(),
    summary: {
      healthy: errorCount === 0,
      errors: errorCount,
      warnings: warningCount,
      totalRoles: ALL_CANONICAL_ROLES.length,
      totalPolicies: ALL_DEFINED_POLICIES.length,
      totalPermissions: ALL_DEFINED_PERMISSIONS.length,
    },
    rolePolicyIntegrity: integrity,
    orphanPolicies: orphans,
    invalidRoleMappings: invalidRoles,
    duplicatePolicies: duplicates,
    crossModuleConsistency: consistency,
    roleCoverage,
    groupCoverage,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 5. DEV-ONLY DIAGNOSTICS RUNNER
// ═══════════════════════════════════════════════════════════════════════════════
//
// Optional one-shot diagnostics output for development mode ONLY.
// This function MUST be called explicitly — it is NEVER called
// automatically during module load, renders, or component lifecycle.
//
// Production safety:
//   - Guarded by import.meta.env.DEV (Vite dev mode check)
//   - Never runs in production builds
//   - Does not spam console (single structured output)
//   - Does not create loops or repeated execution
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Run governance diagnostics and output results to console.
 * Only produces output in development mode (import.meta.env.DEV).
 *
 * Call this explicitly from a dev tool, admin utility, or browser console.
 * It is NEVER called automatically.
 *
 * @param {Object} [options]
 * @param {boolean} [options.verbose=false] - Include per-role detail
 * @param {boolean} [options.forceOutput=false] - Output even in production (testing only)
 *
 * @example
 *   // In browser console during development:
 *   import { runGovernanceDiagnostics } from "./security/governanceDiagnostics";
 *   runGovernanceDiagnostics({ verbose: true });
 */
export function runGovernanceDiagnostics(options = {}) {
  const { verbose = false, forceOutput = false } = options;

  // Guard: only output in dev mode unless forced
  const isDev = typeof import.meta !== "undefined" && import.meta.env?.DEV;
  if (!isDev && !forceOutput) return null;

  const report = generateGovernanceReport();

  // Summary header
  console.group(
    `🏛️ [GOVERNANCE DIAGNOSTICS] ${report.summary.healthy ? "✅ HEALTHY" : "⚠️ ISSUES DETECTED"}`
  );

  console.log(
    `📊 ${report.summary.totalRoles} roles | ${report.summary.totalPolicies} policies | ${report.summary.totalPermissions} permissions`
  );
  console.log(
    `${report.summary.errors > 0 ? "❌" : "✅"} Errors: ${report.summary.errors} | ${report.summary.warnings > 0 ? "⚠️" : "✅"} Warnings: ${report.summary.warnings}`
  );

  // Errors
  if (report.rolePolicyIntegrity.errors.length > 0) {
    console.group("❌ Integrity Errors");
    report.rolePolicyIntegrity.errors.forEach((e) => console.error(e));
    console.groupEnd();
  }

  // Warnings
  if (report.rolePolicyIntegrity.warnings.length > 0) {
    console.group("⚠️ Integrity Warnings");
    report.rolePolicyIntegrity.warnings.forEach((w) => console.warn(w));
    console.groupEnd();
  }

  // Cross-module consistency
  if (!report.crossModuleConsistency.consistent) {
    console.group("🔄 Cross-Module Mismatches");
    report.crossModuleConsistency.mismatches.forEach((m) => console.warn(m));
    console.groupEnd();
  }

  // Orphan policies
  if (report.orphanPolicies.count > 0) {
    console.warn(
      `🔍 Orphan policies: ${report.orphanPolicies.orphanPolicies.join(", ")}`
    );
  }

  // Verbose: per-role coverage
  if (verbose) {
    console.group("📋 Role Coverage");
    console.table(report.roleCoverage);
    console.groupEnd();

    console.group("📦 Policy Group Coverage");
    for (const [group, data] of Object.entries(report.groupCoverage)) {
      console.log(
        `  ${group}: full=[${data.rolesWithFullCoverage.join(",")}] ` +
          `partial=[${data.rolesWithPartialCoverage.join(",")}] ` +
          `none=[${data.rolesWithNoCoverage.join(",")}]`
      );
    }
    console.groupEnd();
  }

  console.groupEnd();

  return report;
}
