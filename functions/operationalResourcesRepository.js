"use strict";

const { getRuntimePool } = require("./db/pool");
const { withTenantTransaction } = require("./db/tenantContext");

const TABLES = Object.freeze({
  cases: { table: "explainsec_cases", id: "case_id" },
  incidents: { table: "explainsec_incidents", id: "incident_id" },
  investigations: { table: "explainsec_investigations", id: "investigation_id" },
  evidence: { table: "explainsec_evidence_metadata", id: "evidence_id" },
  tasks: { table: "explainsec_tasks", id: "task_id" },
  timeline: { table: "explainsec_timeline_entries", id: "timeline_entry_id" },
});
const IDENTIFIER = /^[a-z_]+$/;
function tableFor(type) {
  const value = TABLES[type];
  if (!value) throw new Error(`Unknown operational resource: ${type}`);
  return value;
}
function columns(data) {
  return Object.keys(data).filter((key) => key !== "tenant_id" && IDENTIFIER.test(key));
}

function createOperationalResourcesRepository(pool = getRuntimePool()) {
  return {
    async create(type, tenantId, data) {
      const meta = tableFor(type);
      const keys = columns(data);
      if (!keys.length) throw new Error("Resource fields are required");
      const values = keys.map((key) => data[key]);
      const placeholders = keys.map((_, i) => `$${i + 2}`);
      const result = await withTenantTransaction(pool, tenantId, (client) => client.query(
        `INSERT INTO ${meta.table} (tenant_id, ${keys.join(", ")}) VALUES ($1, ${placeholders.join(", ")}) RETURNING *`,
        [tenantId, ...values]
      ));
      return result.rows[0];
    },
    async get(type, tenantId, id) {
      const meta = tableFor(type);
      const result = await withTenantTransaction(pool, tenantId, (client) =>
        client.query(`SELECT * FROM ${meta.table} WHERE tenant_id = $1 AND ${meta.id} = $2`, [tenantId, id]));
      return result.rows[0] || null;
    },
    async list(type, tenantId) {
      const meta = tableFor(type);
      const result = await withTenantTransaction(pool, tenantId, (client) =>
        client.query(`SELECT * FROM ${meta.table} WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]));
      return result.rows;
    },
    async update(type, tenantId, id, data) {
      const meta = tableFor(type);
      const keys = columns(data);
      if (!keys.length) throw new Error("Resource fields are required");
      const values = keys.map((key) => data[key]);
      const assignments = keys.map((key, i) => `${key} = $${i + 3}`);
      const result = await withTenantTransaction(pool, tenantId, (client) => client.query(
        `UPDATE ${meta.table} SET ${assignments.join(", ")}, updated_at = now() WHERE tenant_id = $1 AND ${meta.id} = $2 RETURNING *`,
        [tenantId, id, ...values]
      ));
      return result.rows[0] || null;
    },
    async remove(type, tenantId, id) {
      const meta = tableFor(type);
      const result = await withTenantTransaction(pool, tenantId, (client) =>
        client.query(`DELETE FROM ${meta.table} WHERE tenant_id = $1 AND ${meta.id} = $2 RETURNING ${meta.id}`, [tenantId, id]));
      return result.rowCount === 1;
    },
  };
}

module.exports = { TABLES, createOperationalResourcesRepository };
