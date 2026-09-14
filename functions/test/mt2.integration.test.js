const test = require("node:test");
const assert = require("node:assert/strict");
const { getRuntimePool, getAdminPool, closePools } = require("../db/pool");
const { resolveSecurityContext } = require("../securityContext");

const configured = Boolean(
  process.env.EXPLAINSEC_PG_RUNTIME_URL && process.env.EXPLAINSEC_PG_ADMIN_URL
);

test("MT-2 PostgreSQL SecurityContext integration", { skip: !configured }, async (t) => {
  const admin = getAdminPool();
  const runtime = getRuntimePool();
  const created = await admin.query(`
    INSERT INTO explainsec_users(display_name) VALUES ('MT2 user')
    RETURNING user_id
  `);
  const userId = created.rows[0].user_id;
  const identity = await admin.query(`
    INSERT INTO explainsec_identities(user_id, provider_type, provider_subject, verified_at)
    VALUES ($1, 'firebase', 'mt2-firebase-user', now()) RETURNING identity_id
  `, [userId]);
  const orgs = await admin.query(`
    INSERT INTO explainsec_organizations(organization_type, name)
    VALUES ('CUSTOMER', 'MT2 A'), ('CUSTOMER', 'MT2 B')
    RETURNING organization_id, name
  `);
  const orgA = orgs.rows.find((row) => row.name === "MT2 A").organization_id;
  const orgB = orgs.rows.find((row) => row.name === "MT2 B").organization_id;
  const tenants = await admin.query(`
    INSERT INTO explainsec_tenants(organization_id, name, slug, status)
    VALUES ($1, 'MT2 Tenant A', 'mt2-a', 'ACTIVE'),
           ($2, 'MT2 Tenant B', 'mt2-b', 'ACTIVE')
    RETURNING tenant_id, organization_id
  `, [orgA, orgB]);
  const tenantA = tenants.rows.find((row) => row.organization_id === orgA).tenant_id;
  const tenantB = tenants.rows.find((row) => row.organization_id === orgB).tenant_id;
  await admin.query(`
    INSERT INTO explainsec_memberships(user_id, organization_id, membership_type, role, status)
    VALUES ($1, $2, 'ORGANIZATION', 'ORGANIZATION_MEMBER', 'ACTIVE')
  `, [userId, orgA]);
  await admin.query(`
    INSERT INTO explainsec_memberships(user_id, organization_id, tenant_id, membership_type, role, status)
    VALUES ($1, $2, $3, 'TENANT', 'TENANT_ADMIN', 'ACTIVE')
  `, [userId, orgA, tenantA]);
  await admin.query(
    "UPDATE explainsec_memberships SET effective_from = now() - interval '1 minute' WHERE user_id = $1",
    [userId]
  );

  t.after(async () => {
    await admin.query(`
      TRUNCATE explainsec_memberships, explainsec_identities, explainsec_users,
        explainsec_tenants, explainsec_organizations CASCADE
    `);
    await closePools();
  });

  await assert.rejects(() => resolveSecurityContext("unknown", { organizationId: orgA }, runtime));
  const orgContext = await resolveSecurityContext(
    "mt2-firebase-user", { organizationId: orgA }, runtime
  );
  assert.deepEqual(orgContext.roles, ["ORGANIZATION_MEMBER"]);
  assert.ok(Object.isFrozen(orgContext));
  assert.throws(() => { orgContext.roles.push("PLATFORM_ADMIN"); }, TypeError);
  const tenantContext = await resolveSecurityContext(
    "mt2-firebase-user", { organizationId: orgA, tenantId: tenantA }, runtime
  );
  assert.deepEqual(tenantContext.roles, ["TENANT_ADMIN"]);
  await assert.rejects(() => resolveSecurityContext(
    "mt2-firebase-user", { organizationId: orgA, tenantId: tenantB }, runtime
  ));
  await assert.rejects(() => resolveSecurityContext(
    "mt2-firebase-user", { organizationId: orgB, tenantId: tenantA }, runtime
  ));
  await assert.rejects(() => resolveSecurityContext(
    "mt2-firebase-user", { tenantId: tenantA }, runtime
  ));
  await assert.rejects(() => resolveSecurityContext(
    "mt2-firebase-user", { organizationId: orgA, organization_id: orgB }, runtime
  ));
  await admin.query(
    "UPDATE explainsec_memberships SET effective_until = now() - interval '1 second' WHERE user_id = $1 AND tenant_id = $2",
    [userId, tenantA]
  );
  await assert.rejects(() => resolveSecurityContext(
    "mt2-firebase-user", { organizationId: orgA, tenantId: tenantA }, runtime
  ));
  assert.equal(identity.rowCount, 1);
});
