const test = require("node:test");
const assert = require("node:assert/strict");
const { getRuntimePool, getAdminPool, closePools } = require("../db/pool");
const { withTenantTransaction } = require("../db/tenantContext");

const configured = Boolean(
  process.env.EXPLAINSEC_PG_RUNTIME_URL && process.env.EXPLAINSEC_PG_ADMIN_URL
);

test("controlled authorization audit boundary", { skip: !configured }, async (t) => {
  const runtime = getRuntimePool();
  const admin = getAdminPool();
  const fixture = await admin.query(`
    WITH u AS (
      INSERT INTO explainsec_users(display_name) VALUES ('Audit test user')
      RETURNING user_id
    ), i AS (
      INSERT INTO explainsec_identities(user_id, provider_type, provider_subject, verified_at)
      SELECT user_id, 'firebase', 'audit-test-subject', now() FROM u
      RETURNING user_id
    ), o AS (
      INSERT INTO explainsec_organizations(organization_type, name)
      VALUES ('CUSTOMER', 'Audit test organization')
      RETURNING organization_id
    ), t AS (
      INSERT INTO explainsec_tenants(organization_id, name, slug, status)
      SELECT organization_id, 'Audit test tenant', 'audit-test', 'ACTIVE' FROM o
      RETURNING tenant_id, organization_id
    )
    INSERT INTO explainsec_memberships(user_id, organization_id, tenant_id, membership_type, role, status)
    SELECT u.user_id, t.organization_id, t.tenant_id, 'TENANT', 'TENANT_ADMIN', 'ACTIVE'
      FROM u CROSS JOIN t
    RETURNING user_id, organization_id, tenant_id, membership_id
  `);
  const { user_id: userId, organization_id: organizationId, tenant_id: tenantId, membership_id: membershipId } =
    fixture.rows[0];

  t.after(async () => {
    await admin.query("ALTER TABLE explainsec_authorization_audit DISABLE TRIGGER USER");
    await admin.query("DELETE FROM explainsec_authorization_audit WHERE user_id = $1", [userId]);
    await admin.query("ALTER TABLE explainsec_authorization_audit ENABLE TRIGGER USER");
    await admin.query("DELETE FROM explainsec_users WHERE user_id = $1", [userId]);
    await closePools();
  });

  const roleState = await admin.query(`
    SELECT r.rolcanlogin, r.rolsuper, r.rolbypassrls,
           has_table_privilege('explainsec_runtime', 'explainsec_authorization_audit', 'SELECT,INSERT,UPDATE,DELETE') AS runtime_table_privileges,
           has_function_privilege('explainsec_runtime',
             'fn_record_authorization_decision(text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,text,boolean,text,text,uuid,text,text,text)',
             'EXECUTE') AS runtime_execute
      FROM pg_roles r
     WHERE r.rolname = 'explainsec_audit_writer'
  `);
  assert.deepEqual(roleState.rows[0], {
    rolcanlogin: false,
    rolsuper: false,
    rolbypassrls: false,
    runtime_table_privileges: false,
    runtime_execute: true,
  });
  const publicExecute = await admin.query(`
    SELECT COALESCE(
      has_function_privilege('public',
        'fn_record_authorization_decision(text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,text,boolean,text,text,uuid,text,text,text)',
        'EXECUTE'),
      false
    ) AS public_execute
  `);
  assert.equal(publicExecute.rows[0].public_execute, false);

  const rls = await admin.query(`
    SELECT relrowsecurity, relforcerowsecurity
      FROM pg_class
     WHERE oid = 'explainsec_authorization_audit'::regclass
  `);
  assert.deepEqual(rls.rows[0], { relrowsecurity: true, relforcerowsecurity: true });

  await assert.rejects(runtime.query("SELECT count(*) FROM explainsec_authorization_audit"));
  await assert.rejects(
    runtime.query(
      "INSERT INTO explainsec_authorization_audit(action, allowed, reason, scope_type, permission, policy_id, decision_version) VALUES ('incident:read', true, 'forged', 'TENANT', 'incident:read', 'mt3.test', 'mt3.v1')"
    )
  );

  await assert.rejects(
    runtime.query("UPDATE explainsec_authorization_audit SET reason = 'forged'")
  );
  await assert.rejects(
    runtime.query("DELETE FROM explainsec_authorization_audit")
  );

  await assert.rejects(
    runtime.query(
      "SELECT fn_record_authorization_decision($1,$2,$3,$4,NULL,NULL,NULL,NULL,$5,$6,true,$7,$8,NULL,NULL,$9,$10)",
      ["TENANT", userId, membershipId, organizationId, "incident:read", "incident:read", "allowed", "mt3.test", "request-no-context", "mt3.v1"]
    )
  );

  const inserted = await withTenantTransaction(runtime, tenantId, (client) =>
    client.query(
      "SELECT fn_record_authorization_decision($1,$2,$3,$4,NULL,NULL,NULL,NULL,$5,$6,true,$7,$8,NULL,NULL,$9,$10) AS audit_id",
      ["TENANT", userId, membershipId, organizationId, "incident:read", "incident:read", "allowed", "mt3.test", "request-1", "mt3.v1"]
    )
  );
  assert.match(inserted.rows[0].audit_id, /^[0-9a-f-]{36}$/);

  await assert.rejects(
    runtime.query(
      "SELECT fn_record_authorization_decision($1,$2,NULL,NULL,$3,$4,$5,$6,$7,$8,true,$9,$10,NULL,NULL,$11,$12)",
      ["PORTFOLIO", userId, "00000000-0000-4000-8000-000000000001",
        organizationId, "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000003", "incident:read",
        "incident:read", "inconsistent", "mt3.test", "request-portfolio", "mt3.v1"]
    )
  );

  await assert.rejects(
    withTenantTransaction(runtime, tenantId, (client) =>
      client.query(
        "UPDATE explainsec_authorization_audit SET reason = 'changed' WHERE audit_id = $1",
        [inserted.rows[0].audit_id]
      )
    )
  );
  await assert.rejects(
    withTenantTransaction(runtime, tenantId, (client) =>
      client.query("DELETE FROM explainsec_authorization_audit WHERE audit_id = $1", [inserted.rows[0].audit_id])
    )
  );
});
