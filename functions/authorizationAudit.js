"use strict";

const SCOPES = new Set(["TENANT", "ORGANIZATION", "PORTFOLIO", "PLATFORM"]);

function requiredString(value, field, maxLength) {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength) {
    throw new Error(`Invalid authorization audit ${field}`);
  }
  return value;
}

function createAuthorizationAuditEnvelope({ context, decision, resource = {}, metadata = {} }) {
  if (!context || typeof context !== "object") throw new Error("SecurityContext is required");
  if (!decision || typeof decision !== "object") throw new Error("Policy decision is required");
  const scopeType = requiredString(
    context.scopeType || resource.scopeType ||
      (context.tenantId ? "TENANT" : context.portfolioId ? "PORTFOLIO" : "ORGANIZATION"),
    "scope",
    32
  );
  if (!SCOPES.has(scopeType)) throw new Error("Invalid authorization audit scope");
  const action = requiredString(decision.action, "action", 128);
  const permission = requiredString(
    decision.matchedPermissions && decision.matchedPermissions[0] || "none",
    "permission",
    128
  );
  const policyId = requiredString(decision.policyId, "policyId", 128);
  const reason = requiredString(decision.reason, "reason", 512);
  const decisionVersion = requiredString(metadata.decisionVersion || "mt3.v1", "decisionVersion", 128);
  return Object.freeze({
    scopeType,
    userId: context.userId || null,
    membershipId: context.activeMembershipId || null,
    organizationId: context.organizationId || null,
    vendorOrganizationId: context.vendorOrganizationId || null,
    customerOrganizationId: resource.customerOrganizationId || null,
    portfolioId: context.portfolioId || null,
    relationshipId: resource.relationshipId || null,
    action,
    permission,
    allowed: decision.allowed === true,
    reason,
    policyId,
    resourceId: resource.id || resource.resourceId || null,
    resourceType: resource.type || resource.resourceType || null,
    requestId: metadata.requestId || context.requestId || null,
    decisionVersion,
  });
}

module.exports = { createAuthorizationAuditEnvelope };
