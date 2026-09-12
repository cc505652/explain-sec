"use strict";

/**
 * MT-3 canonical authorization boundary.
 *
 * This module is deliberately independent of Firebase, Firestore, and the
 * client. Callers provide an already authenticated subject and a resource
 * snapshot. Missing or malformed facts are never interpreted optimistically.
 */

const ROLES = Object.freeze({
  PLATFORM_ADMIN: "PLATFORM_ADMIN",
  ORGANIZATION_OWNER: "ORGANIZATION_OWNER",
  ORGANIZATION_ADMIN: "ORGANIZATION_ADMIN",
  ORGANIZATION_MEMBER: "ORGANIZATION_MEMBER",
  TENANT_ADMIN: "TENANT_ADMIN",
  VENDOR_MEMBER: "VENDOR_MEMBER",
  SOC_L1: "SOC_L1",
  SOC_L2: "SOC_L2",
  SOC_MANAGER: "SOC_MANAGER",
  INCIDENT_RESPONDER: "INCIDENT_RESPONDER",
  THREAT_HUNTER: "THREAT_HUNTER",
  MSSP_ANALYST: "MSSP_ANALYST",
});

const PERMISSIONS = Object.freeze({
  SOC_READ: "soc:read",
  SOC_WRITE: "soc:write",
  SOC_ADMIN: "soc:admin",
  USER_ADMIN: "user:admin",
  INCIDENT_READ: "incident:read",
  INCIDENT_WRITE: "incident:write",
  GOVERNANCE_WRITE: "governance:write",
  CASE_READ: "case:read",
  CASE_WRITE: "case:write",
  INVESTIGATION_READ: "investigation:read",
  INVESTIGATION_WRITE: "investigation:write",
  EVIDENCE_READ: "evidence:read",
  EVIDENCE_WRITE: "evidence:write",
  TASK_READ: "task:read",
  TASK_WRITE: "task:write",
  TIMELINE_READ: "timeline:read",
  TIMELINE_APPEND: "timeline:append",
});

const ROLE_PERMISSIONS = Object.freeze({
  [ROLES.PLATFORM_ADMIN]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.SOC_WRITE, PERMISSIONS.SOC_ADMIN,
    PERMISSIONS.USER_ADMIN, PERMISSIONS.INCIDENT_READ, PERMISSIONS.INCIDENT_WRITE,
    PERMISSIONS.GOVERNANCE_WRITE,
  ]),
  [ROLES.ORGANIZATION_OWNER]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.SOC_WRITE, PERMISSIONS.USER_ADMIN,
    PERMISSIONS.INCIDENT_READ, PERMISSIONS.INCIDENT_WRITE, PERMISSIONS.GOVERNANCE_WRITE,
  ]),
  [ROLES.ORGANIZATION_ADMIN]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.SOC_WRITE, PERMISSIONS.USER_ADMIN,
    PERMISSIONS.INCIDENT_READ, PERMISSIONS.INCIDENT_WRITE,
  ]),
  [ROLES.ORGANIZATION_MEMBER]: Object.freeze([PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ]),
  [ROLES.TENANT_ADMIN]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.SOC_WRITE, PERMISSIONS.INCIDENT_READ,
    PERMISSIONS.INCIDENT_WRITE, PERMISSIONS.CASE_READ, PERMISSIONS.CASE_WRITE,
    PERMISSIONS.INVESTIGATION_READ, PERMISSIONS.INVESTIGATION_WRITE,
    PERMISSIONS.EVIDENCE_READ, PERMISSIONS.EVIDENCE_WRITE,
    PERMISSIONS.TASK_READ, PERMISSIONS.TASK_WRITE,
    PERMISSIONS.TIMELINE_READ, PERMISSIONS.TIMELINE_APPEND,
  ]),
  [ROLES.VENDOR_MEMBER]: Object.freeze([PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ]),
  [ROLES.SOC_L1]: Object.freeze([PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ]),
  [ROLES.SOC_L2]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ, PERMISSIONS.INCIDENT_WRITE,
  ]),
  [ROLES.SOC_MANAGER]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ, PERMISSIONS.INCIDENT_WRITE,
    PERMISSIONS.GOVERNANCE_WRITE,
  ]),
  [ROLES.INCIDENT_RESPONDER]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ, PERMISSIONS.INCIDENT_WRITE,
  ]),
  [ROLES.THREAT_HUNTER]: Object.freeze([
    PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ,
  ]),
  [ROLES.MSSP_ANALYST]: Object.freeze([PERMISSIONS.SOC_READ, PERMISSIONS.INCIDENT_READ]),
});

const ACTION_PERMISSIONS = Object.freeze({
  "soc:read": PERMISSIONS.SOC_READ,
  "soc:write": PERMISSIONS.SOC_WRITE,
  "soc:admin": PERMISSIONS.SOC_ADMIN,
  "user:admin": PERMISSIONS.USER_ADMIN,
  "incident:read": PERMISSIONS.INCIDENT_READ,
  "incident:write": PERMISSIONS.INCIDENT_WRITE,
  "governance:write": PERMISSIONS.GOVERNANCE_WRITE,
  "case:read": PERMISSIONS.CASE_READ,
  "case:create": PERMISSIONS.CASE_WRITE,
  "case:update": PERMISSIONS.CASE_WRITE,
  "case:close": PERMISSIONS.CASE_WRITE,
  "incident:create": PERMISSIONS.INCIDENT_WRITE,
  "investigation:read": PERMISSIONS.INVESTIGATION_READ,
  "investigation:create": PERMISSIONS.INVESTIGATION_WRITE,
  "investigation:update": PERMISSIONS.INVESTIGATION_WRITE,
  "evidence:read": PERMISSIONS.EVIDENCE_READ,
  "evidence:add": PERMISSIONS.EVIDENCE_WRITE,
  "evidence:update": PERMISSIONS.EVIDENCE_WRITE,
  "evidence:delete": PERMISSIONS.EVIDENCE_WRITE,
  "task:read": PERMISSIONS.TASK_READ,
  "task:create": PERMISSIONS.TASK_WRITE,
  "task:update": PERMISSIONS.TASK_WRITE,
  "task:assign": PERMISSIONS.TASK_WRITE,
  "timeline:read": PERMISSIONS.TIMELINE_READ,
  "timeline:append": PERMISSIONS.TIMELINE_APPEND,
});

const ACTIVE_LIFECYCLE = new Set(["ACTIVE", "OPEN", "ASSIGNED", "IN_PROGRESS",
  "CONFIRMED_THREAT", "ESCALATION_PENDING", "ESCALATION_APPROVED",
  "IR_IN_PROGRESS", "CONTAINMENT_PENDING", "CONTAINMENT_IN_PROGRESS"]);

function decision(allowed, reason, input = {}, details = {}) {
  return Object.freeze({
    allowed,
    effect: allowed ? "ALLOW" : "DENY",
    reason,
    policyId: details.policyId || "mt3.default_deny",
    matchedPermissions: Object.freeze(details.matchedPermissions || []),
    evaluatedScope: Object.freeze(details.evaluatedScope || {}),
    action: input.action || null,
    subjectId: input.subject && (input.subject.userId || input.subject.uid) || null,
    resourceId: input.resource && (input.resource.id || input.resource.resourceId) || null,
    tenantId: input.resource && input.resource.tenantId || input.tenant && input.tenant.tenantId || null,
  });
}

function subjectRoles(subject) {
  if (!subject || typeof subject !== "object") return [];
  const roles = Array.isArray(subject.roles) ? subject.roles : subject.role ? [subject.role] : [];
  return roles.filter((role) => typeof role === "string" && Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role));
}

function subjectScope(subject, key) {
  const values = new Set(Array.isArray(subject[key]) ? subject[key] : []);
  if (Array.isArray(subject.memberships)) {
    subject.memberships.forEach((membership) => {
      const value = key === "tenantIds" ? membership.tenantId : membership.organizationId;
      if (value) values.add(value);
    });
  }
  if (key === "organizationIds" && Array.isArray(subject.msspMemberships)) {
    subject.msspMemberships.forEach((membership) => {
      if (membership.customerOrganizationId) values.add(membership.customerOrganizationId);
    });
  }

  return values;
}

function serverTenantScope(subject) {
  if (Array.isArray(subject && subject.effectiveTenantIds)) {
    return new Set(subject.effectiveTenantIds);
  }
  return subjectScope(subject, "tenantIds");
}

function evaluatePolicy(input = {}) {
  const { subject, resource, action, tenant, environment = {} } = input;
  if (!subject || typeof subject !== "object") return decision(false, "MISSING_SUBJECT", input);
  if (!resource || typeof resource !== "object") return decision(false, "MISSING_RESOURCE", input);
  if (typeof action !== "string" || !ACTION_PERMISSIONS[action]) {
    return decision(false, "UNKNOWN_ACTION", input);
  }
  if (subject.status && subject.status !== "ACTIVE") return decision(false, "SUBJECT_INACTIVE", input);
  const roles = subjectRoles(subject);
  if (!roles.length) return decision(false, "UNKNOWN_ROLE", input);
  const required = ACTION_PERMISSIONS[action];
  const permissions = new Set(roles.flatMap((role) => ROLE_PERMISSIONS[role]));
  if (!permissions.has(required)) return decision(false, "PERMISSION_DENIED", input);

  const requestedTenant = resource.tenantId || (tenant && tenant.tenantId);
  const subjectTenants = serverTenantScope(subject);
  const subjectOrganizations = subjectScope(subject, "organizationIds");
  if (!requestedTenant && resource.requiresTenant !== false) return decision(false, "MISSING_TENANT_SCOPE", input);
  if (requestedTenant && !subjectTenants.has(requestedTenant)) {
    return decision(false, "TENANT_SCOPE_DENIED", input);
  }
  if (resource.organizationId && !subjectOrganizations.has(resource.organizationId)) {
    return decision(false, "ORGANIZATION_SCOPE_DENIED", input);
  }
  if (resource.vendorOrganizationId &&
      subject.vendorOrganizationId &&
      resource.vendorOrganizationId !== subject.vendorOrganizationId) {
    return decision(false, "VENDOR_SCOPE_DENIED", input);
  }
  if (resource.portfolioId && Array.isArray(subject.msspMemberships) &&
      !subject.msspMemberships.some((membership) =>
        membership.portfolioId === resource.portfolioId &&
        (!resource.tenantId || membership.tenantId === resource.tenantId))) {
    return decision(false, "PORTFOLIO_SCOPE_DENIED", input);
  }
  if (resource.relationshipStatus && resource.relationshipStatus !== "ACTIVE") {
    return decision(false, "RELATIONSHIP_INACTIVE", input);
  }
  if (resource.grantStatus && resource.grantStatus !== "ACTIVE") {
    return decision(false, "GRANT_INACTIVE", input);
  }
  if (resource.ownerUserId && resource.ownerUserId !== (subject.userId || subject.uid) &&
      resource.ownerOnly === true) return decision(false, "RESOURCE_OWNER_REQUIRED", input);

  // MSSP access is an explicit boundary. Vendor membership is never a
  // wildcard over customer data, even when the customer tenant is known.
  if (roles.some((role) => role === ROLES.VENDOR_MEMBER || role === ROLES.MSSP_ANALYST) &&
      resource.organizationType === "CUSTOMER" &&
      resource.msspAccess !== true) return decision(false, "MSSP_BOUNDARY_DENIED", input);

  if (resource.status && !ACTIVE_LIFECYCLE.has(String(resource.status).toUpperCase()) &&
      resource.allowInactive !== true) return decision(false, "LIFECYCLE_DENIED", input);
  if (Array.isArray(resource.allowedActions) && !resource.allowedActions.includes(action)) {
    return decision(false, "LIFECYCLE_ACTION_DENIED", input);
  }
  if (typeof input.separationOfDuties === "function" &&
      input.separationOfDuties({ subject, resource, action }) === false) {
    return decision(false, "SEPARATION_OF_DUTIES_DENIED", input);
  }
  if (typeof input.delegation === "function" &&
      input.delegation({ subject, resource, action }) === false) {
    return decision(false, "DELEGATION_DENIED", input);
  }
  if (environment.requireRlsHandoff === true && environment.rlsTenantId !== requestedTenant) {
    return decision(false, "RLS_HANDOFF_REQUIRED", input);
  }
  return decision(true, "POLICY_MATCH", input, {
    policyId: "mt3.rbac-abac.default",
    matchedPermissions: [required],
    evaluatedScope: {
      organizationId: resource.organizationId || null,
      tenantId: requestedTenant || null,
    },
  });
}

function authorize(input = {}) {
  const result = evaluatePolicy(input);
  if (typeof input.logger === "function") {
    input.logger({ ...result, loggedAt: new Date().toISOString() });
  }
  if (!result.allowed && input.throwOnDeny === true) {
    throw new AuthorizationError(result);
  }
  return result;
}

class AuthorizationError extends Error {
  constructor(result) {
    super(`Authorization denied: ${result.reason}`);
    this.name = "AuthorizationError";
    this.code = "PERMISSION_DENIED";
    this.decision = result;
  }
}

module.exports = {
  ROLES,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  ACTION_PERMISSIONS,
  evaluatePolicy,
  authorize,
  AuthorizationError,
};
