const test = require("node:test");
const assert = require("node:assert/strict");
const { getRuntimePool, getAdminPool, closePools } = require("../db/pool");
const { withTenantTransaction } = require("../db/tenantContext");
const { authorize } = require("../policyEngine");

const configured = Boolean(
  process.env.EXPLAINSEC_PG_RUNTIME_URL && process.env.EXPLAINSEC_PG_ADMIN_URL
);

test("MT-3 PostgreSQL RBAC/ABAC policy boundary", { skip: !configured }, async (t) => {
  const admin = getAdminPool();
  const runtime = getRuntimePool();
  const user = await admin.query(
    "INSERT INTO explainsec_users(display_name) VALUES ('MT3 user') RETURNING user_id"
  );
  const org = await admin.query(
    "INSERT INTO explainsec_organizations(organization_type, name) VALUES ('CUSTOMER', 'MT3 org') RETURNING organization_id"
  );
  const tenant = await admin.query(
    "INSERT INTO explainsec_tenants(organization_id, name, slug, status) VALUES ($1, 'MT3 tenant', 'mt3', 'ACTIVE') RETURNING tenant_id",
    [org.rows[0].organization_id]
  );
  const userId = user.rows[0].user_id;
  const organizationId = org.rows[0].organization_id;
  const tenantId = tenant.rows[0].tenant_id;
  await admin.query(`
    INSERT INTO explainsec_memberships(user_id, organization_id, tenant_id, membership_type, role, status)
    VALUES ($1, $2, $3, 'TENANT', 'TENANT_ADMIN', 'ACTIVE')
  `, [userId, organizationId, tenantId]);

  t.after(async () => {
    await admin.query("TRUNCATE explainsec_memberships, explainsec_users, explainsec_tenants, explainsec_organizations CASCADE");
    await closePools();
  });

  const subject = {
    userId, roles: ["TENANT_ADMIN"], status: "ACTIVE",
    memberships: [{ organizationId, tenantId }],
  };
  const resource = { id: "incident-1", organizationId, tenantId, status: "ACTIVE" };
  const allowed = authorize({ subject, resource, action: "incident:read" });
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.policyId, "mt3.rbac-abac.default");
  assert.deepEqual(allowed.matchedPermissions, ["incident:read"]);
  assert.deepEqual(allowed.evaluatedScope, { organizationId, tenantId });
  assert.equal(authorize({ subject, resource, action: "governance:write" }).allowed, false);
  assert.equal(authorize({
    subject, resource: { ...resource, tenantId: "00000000-0000-4000-8000-000000000000" },
    action: "incident:read",
  }).reason, "TENANT_SCOPE_DENIED");
  assert.equal(authorize({
    subject: { ...subject, roles: ["PLATFORM_ADMIN"], memberships: [] },
    resource, action: "incident:read",
  }).reason, "TENANT_SCOPE_DENIED");
  assert.equal(authorize({
    subject, resource: { ...resource, status: "DELETED" }, action: "incident:read",
  }).reason, "LIFECYCLE_DENIED");
  assert.equal(authorize({
    subject, resource, action: "not-a-permission",
  }).reason, "UNKNOWN_ACTION");
  assert.equal(authorize({
    subject: { ...subject, roles: ["PLATFORM_SUPERUSER"] }, resource,
    action: "incident:read",
  }).reason, "UNKNOWN_ROLE");
  assert.equal(authorize({ subject, resource: {}, action: "incident:read" }).reason,
    "MISSING_TENANT_SCOPE");
  assert.equal(authorize({ resource, action: "incident:read" }).reason, "MISSING_SUBJECT");
  assert.equal(authorize({
    subject: { ...subject, roles: ["VENDOR_MEMBER"] },
    resource: { ...resource, organizationType: "CUSTOMER" },
    action: "incident:read",
  }).reason, "MSSP_BOUNDARY_DENIED");
  const rls = await withTenantTransaction(runtime, tenantId, (client) =>
    client.query("SELECT count(*) FROM explainsec_mt1_rls_probe")
  );
  assert.equal(rls.rows[0].count, "0");
});
