const test = require("node:test");
const assert = require("node:assert/strict");
const { getRuntimePool, getAdminPool, closePools } = require("../db/pool");
const { assertRuntimeRoleNoBypassRls } = require("../db/runtimeRole");
const { withTenantTransaction } = require("../db/tenantContext");

const configured = Boolean(
  process.env.EXPLAINSEC_PG_RUNTIME_URL && process.env.EXPLAINSEC_PG_ADMIN_URL
);

test("MT-1 integration tests require configured PostgreSQL roles", { skip: !configured }, async (t) => {
  const runtime = getRuntimePool();
  const admin = getAdminPool();
  await assertRuntimeRoleNoBypassRls(runtime);
  const role = await admin.query(
    "SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname = 'explainsec_runtime'"
  );
  assert.equal(role.rows[0].rolbypassrls, false);
  const rls = await admin.query(`
    SELECT relrowsecurity, relforcerowsecurity
    FROM pg_class
    WHERE oid = 'explainsec_mt1_rls_probe'::regclass
  `);
  assert.deepEqual(rls.rows[0], { relrowsecurity: true, relforcerowsecurity: true });
  const policies = await admin.query(`
    SELECT policyname, cmd, qual IS NOT NULL AS has_using,
      with_check IS NOT NULL AS has_with_check
    FROM pg_policies
    WHERE tablename = 'explainsec_mt1_rls_probe'
    ORDER BY policyname
  `);
  assert.deepEqual(policies.rows, [
    { policyname: "explainsec_mt1_rls_probe_delete", cmd: "DELETE", has_using: true, has_with_check: false },
    { policyname: "explainsec_mt1_rls_probe_insert", cmd: "INSERT", has_using: false, has_with_check: true },
    { policyname: "explainsec_mt1_rls_probe_select", cmd: "SELECT", has_using: true, has_with_check: false },
    { policyname: "explainsec_mt1_rls_probe_update", cmd: "UPDATE", has_using: true, has_with_check: true },
  ]);
  const setup = await admin.query(`
    INSERT INTO explainsec_organizations(organization_type, name)
    VALUES ('CUSTOMER', 'MT-1 test organization')
    RETURNING organization_id
  `);
  const organizationId = setup.rows[0].organization_id;
  const tenants = await admin.query(`
    INSERT INTO explainsec_tenants(organization_id, name, slug, status)
    VALUES ($1, 'Tenant A', 'mt1-a', 'ACTIVE'), ($1, 'Tenant B', 'mt1-b', 'ACTIVE')
    RETURNING tenant_id, slug
  `, [organizationId]);
  const tenantA = tenants.rows.find((row) => row.slug === "mt1-a").tenant_id;
  const tenantB = tenants.rows.find((row) => row.slug === "mt1-b").tenant_id;

  t.after(async () => {
    await admin.query(`
      TRUNCATE explainsec_memberships, explainsec_identities, explainsec_users,
        explainsec_mt1_rls_probe, explainsec_tenants, explainsec_organizations CASCADE
    `);
    await closePools();
  });

  await withTenantTransaction(runtime, tenantA, (client) =>
    client.query(
      "INSERT INTO explainsec_mt1_rls_probe(tenant_id, value) VALUES ($1, 'A')",
      [tenantA]
    )
  );
  await withTenantTransaction(runtime, tenantB, (client) =>
    client.query(
      "INSERT INTO explainsec_mt1_rls_probe(tenant_id, value) VALUES ($1, 'B')",
      [tenantB]
    )
  );
  const own = await withTenantTransaction(runtime, tenantA, (client) =>
    client.query("SELECT value FROM explainsec_mt1_rls_probe ORDER BY value")
  );
  assert.deepEqual(own.rows.map((row) => row.value), ["A"]);

  const crossTenantUpdate = await withTenantTransaction(runtime, tenantA, (client) =>
    client.query("UPDATE explainsec_mt1_rls_probe SET value = 'changed' WHERE tenant_id = $1", [tenantB])
  );
  assert.equal(crossTenantUpdate.rowCount, 0);
  const crossTenantDelete = await withTenantTransaction(runtime, tenantA, (client) =>
    client.query("DELETE FROM explainsec_mt1_rls_probe WHERE tenant_id = $1", [tenantB])
  );
  assert.equal(crossTenantDelete.rowCount, 0);

  await assert.rejects(
    withTenantTransaction(runtime, tenantA, (client) =>
      client.query(
        "INSERT INTO explainsec_mt1_rls_probe(tenant_id, value) VALUES ($1, 'forged')",
        [tenantB]
      )
    )
  );
  const withoutContext = await runtime.query("SELECT count(*) FROM explainsec_mt1_rls_probe");
  assert.equal(withoutContext.rows[0].count, "0");
  await assert.rejects(
    withTenantTransaction(runtime, "not-a-uuid", () => Promise.resolve())
  );
  const nonexistentTenant = await withTenantTransaction(
    runtime,
    "00000000-0000-4000-8000-000000000000",
    (client) => client.query("SELECT count(*) FROM explainsec_mt1_rls_probe")
  );
  assert.equal(nonexistentTenant.rows[0].count, "0");

  const transactionClient = await runtime.connect();
  try {
    await transactionClient.query("BEGIN");
    await transactionClient.query("SELECT set_config('app.current_tenant_id', $1, true)", [tenantA]);
    const transactionRows = await transactionClient.query("SELECT count(*) FROM explainsec_mt1_rls_probe");
    assert.equal(transactionRows.rows[0].count, "1");
    await transactionClient.query("COMMIT");
    const clearedRows = await transactionClient.query("SELECT count(*) FROM explainsec_mt1_rls_probe");
    assert.equal(clearedRows.rows[0].count, "0");
  } finally {
    transactionClient.release();
  }

  const [concurrentA, concurrentB] = await Promise.all([
    withTenantTransaction(runtime, tenantA, async (client) => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      return client.query("SELECT value FROM explainsec_mt1_rls_probe");
    }),
    withTenantTransaction(runtime, tenantB, async (client) => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return client.query("SELECT value FROM explainsec_mt1_rls_probe");
    }),
  ]);
  assert.deepEqual(concurrentA.rows.map((row) => row.value), ["A"]);
  assert.deepEqual(concurrentB.rows.map((row) => row.value), ["B"]);

  const user = await admin.query(
    "INSERT INTO explainsec_users(display_name) VALUES ('MT-1 user') RETURNING user_id"
  );
  const userId = user.rows[0].user_id;
  const ownerUser = await admin.query(
    "INSERT INTO explainsec_users(display_name) VALUES ('MT-1 owner') RETURNING user_id"
  );
  const ownerUserId = ownerUser.rows[0].user_id;
  const orgB = await admin.query(
    "INSERT INTO explainsec_organizations(organization_type, name) VALUES ('CUSTOMER', 'MT-1 organization B') RETURNING organization_id"
  );
  const organizationB = orgB.rows[0].organization_id;
  const tenantBOrg = await admin.query(
    "INSERT INTO explainsec_tenants(organization_id, name, slug, status) VALUES ($1, 'Tenant B Org', 'mt1-b-org', 'ACTIVE') RETURNING tenant_id",
    [organizationB]
  );
  const tenantBFromOtherOrg = tenantBOrg.rows[0].tenant_id;
  await admin.query(`
    INSERT INTO explainsec_memberships(user_id, organization_id, tenant_id, membership_type, role, status)
    VALUES ($1, $2, NULL, 'ORGANIZATION', 'ORGANIZATION_MEMBER', 'ACTIVE'),
           ($1, $2, $3, 'TENANT', 'TENANT_ADMIN', 'ACTIVE')
  `, [userId, organizationId, tenantA]);
  const membershipCount = await admin.query(
    "SELECT count(*) FROM explainsec_memberships WHERE user_id = $1 AND organization_id = $2",
    [userId, organizationId]
  );
  assert.equal(membershipCount.rows[0].count, "2");
  const tenantA2 = await admin.query(
    "SELECT tenant_id FROM explainsec_tenants WHERE organization_id = $1 AND slug = 'mt1-b'",
    [organizationId]
  );
  assert.notEqual(tenantA2.rows[0].tenant_id, tenantA);
  const crossOrgRows = await withTenantTransaction(runtime, tenantA, (client) =>
    client.query("SELECT count(*) FROM explainsec_mt1_rls_probe WHERE tenant_id = $1", [tenantBFromOtherOrg])
  );
  assert.equal(crossOrgRows.rows[0].count, "0");

  const owners = await admin.query(`
    INSERT INTO explainsec_memberships(user_id, organization_id, membership_type, role, status)
    VALUES ($1, $2, 'ORGANIZATION', 'ORGANIZATION_OWNER', 'ACTIVE'),
           ($3, $2, 'ORGANIZATION', 'ORGANIZATION_OWNER', 'ACTIVE')
    RETURNING membership_id
  `, [userId, organizationId, ownerUserId]);
  assert.equal(owners.rowCount, 2);
  const ownerClient = await admin.connect();
  try {
    await ownerClient.query("BEGIN");
    await ownerClient.query("DELETE FROM explainsec_memberships WHERE membership_id = $1", [owners.rows[0].membership_id]);
    await ownerClient.query("COMMIT");
    await ownerClient.query("BEGIN");
    await ownerClient.query("DELETE FROM explainsec_memberships WHERE membership_id = $1", [owners.rows[1].membership_id]);
    await assert.rejects(ownerClient.query("COMMIT"));
    await ownerClient.query("ROLLBACK").catch(() => {});
  } finally {
    ownerClient.release();
  }

});
