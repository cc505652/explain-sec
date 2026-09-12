"use strict";

const { authorize } = require("./policyEngine");
const { validateTenantId } = require("./db/tenantContext");
const { createOperationalResourcesRepository } = require("./operationalResourcesRepository");

function requireContext(context) {
  if (!context || typeof context !== "object" || !context.tenantId) {
    throw new Error("A tenant-scoped SecurityContext is required");
  }
  validateTenantId(context.tenantId);
  if (context.status && context.status !== "ACTIVE" && context.userStatus !== "ACTIVE") {
    throw new Error("SecurityContext is inactive");
  }
  return context;
}

function decision(context, type, action, resource) {
  const result = authorize({
    subject: context,
    resource: { ...(resource || {}), id: resource && resource.id, tenantId: context.tenantId },
    action,
    tenant: { tenantId: context.tenantId },
    environment: { requireRlsHandoff: true, rlsTenantId: context.tenantId },
    throwOnDeny: true,
  });
  return result;
}

function createOperationalResourcesService(repository = createOperationalResourcesRepository()) {
  const actions = {
    cases: { create: "case:create", read: "case:read", update: "case:update", remove: "case:close" },
    incidents: { create: "incident:create", read: "incident:read", update: "incident:write", remove: "incident:write" },
    investigations: { create: "investigation:create", read: "investigation:read", update: "investigation:update", remove: "investigation:update" },
    evidence: { create: "evidence:add", read: "evidence:read", update: "evidence:update", remove: "evidence:delete" },
    tasks: { create: "task:create", read: "task:read", update: "task:update", remove: "task:update" },
    timeline: { create: "timeline:append", read: "timeline:read", update: null, remove: null },
  };
  function actionFor(type, operation) {
    if (!actions[type] || actions[type][operation] === undefined) {
      throw new Error(`Unsupported operational resource: ${type}`);
    }
    if (!actions[type][operation]) throw new Error("Timeline entries are append-only");
    return actions[type][operation];
  }
  return {
    async create(context, type, input) {
      const scoped = requireContext(context);
      decision(scoped, type, actionFor(type, "create"), { status: input && input.status || "OPEN" });
      if (input && input.tenant_id && input.tenant_id !== scoped.tenantId) {
        throw new Error("Client tenant selectors are not authoritative");
      }
      const data = { ...(input || {}) };
      delete data.tenantId; delete data.tenant_id;
      return repository.create(type, scoped.tenantId, data);
    },
    async get(context, type, id) {
      const scoped = requireContext(context);
      const existing = await repository.get(type, scoped.tenantId, id);
      if (!existing) return null;
      decision(scoped, type, actionFor(type, "read"), { id, status: existing.status || "ACTIVE" });
      return existing;
    },
    async list(context, type) {
      const scoped = requireContext(context);
      decision(scoped, type, actionFor(type, "read"), { status: "OPEN" });
      return repository.list(type, scoped.tenantId);
    },
    async update(context, type, id, input) {
      const scoped = requireContext(context);
      const action = actionFor(type, "update");
      const existing = await repository.get(type, scoped.tenantId, id);
      if (!existing) return null;
      decision(scoped, type, action, { id, status: existing.status || "ACTIVE" });
      const data = { ...(input || {}) };
      delete data.tenantId; delete data.tenant_id;
      return repository.update(type, scoped.tenantId, id, data);
    },
    async remove(context, type, id) {
      const scoped = requireContext(context);
      actionFor(type, "remove");
      const existing = await repository.get(type, scoped.tenantId, id);
      if (!existing) return false;
      decision(scoped, type, actionFor(type, "remove"), { id, status: existing.status || "ACTIVE" });
      return repository.remove(type, scoped.tenantId, id);
    },
  };
}

module.exports = { createOperationalResourcesService, requireContext };
