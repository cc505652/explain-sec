const test = require("node:test");
const assert = require("node:assert/strict");
const { getRuntimePool, getAdminPool, closePools } = require("../db/pool");
const { withTenantTransaction } = require("../db/tenantContext");
const { createOperationalResourcesService } = require("../operationalResourcesService");

const configured = Boolean(process.env.EXPLAINSEC_PG_RUNTIME_URL && process.env.EXPLAINSEC_PG_ADMIN_URL);

test("MT-4 tenant-owned operational resources", { skip: !configured }, async (t) => {
  const admin = getAdminPool();
  const runtime = getRuntimePool();
  const org = await admin.query("INSERT INTO explainsec_organizations(organization_type, name) VALUES ('CUSTOMER', 'MT4') RETURNING organization_id");
  const tenants = await admin.query(
    "INSERT INTO explainsec_tenants(organization_id, name, slug, status) VALUES ($1,'A','mt4-a','ACTIVE'),($1,'B','mt4-b','ACTIVE') RETURNING tenant_id,slug",
    [org.rows[0].organization_id]
  );
  const tenantA = tenants.rows.find((row) => row.slug === "mt4-a").tenant_id;
  const tenantB = tenants.rows.find((row) => row.slug === "mt4-b").tenant_id;
  t.after(async () => {
    await admin.query("TRUNCATE explainsec_memberships, explainsec_users, explainsec_timeline_entries, explainsec_tasks, explainsec_evidence_metadata, explainsec_investigations, explainsec_incidents, explainsec_cases, explainsec_tenants, explainsec_organizations CASCADE");
    await closePools();
  });

  const user = await admin.query("INSERT INTO explainsec_users(display_name) VALUES ('MT4') RETURNING user_id");
  const userId = user.rows[0].user_id;
  await admin.query(
    "INSERT INTO explainsec_memberships(user_id, organization_id, tenant_id, membership_type, role, status) VALUES ($1,$2,$3,'TENANT','TENANT_ADMIN','ACTIVE')",
    [userId, org.rows[0].organization_id, tenantA]
  );
  const context = { userId, uid: userId, roles: ["TENANT_ADMIN"], status: "ACTIVE", tenantId: tenantA, memberships: [{ tenantId: tenantA, organizationId: org.rows[0].organization_id }] };
  const service = createOperationalResourcesService();
  const created = await service.create(context, "cases", { title: "A case" });
  assert.equal((await service.list(context, "cases")).length, 1);
  assert.equal((await service.get(context, "cases", created.case_id)).tenant_id, tenantA);
  assert.equal((await withTenantTransaction(runtime, tenantB, (client) => client.query("SELECT count(*) FROM explainsec_cases"))).rows[0].count, "0");
  await assert.rejects(() => service.create(context, "cases", { tenant_id: tenantB, title: "forged" }));

  const incident = await service.create(context, "incidents", { case_id: created.case_id, title: "Incident" });
  const investigation = await service.create(context, "investigations", {
    case_id: created.case_id, incident_id: incident.incident_id, title: "Investigation",
  });
  await assert.rejects(() => admin.query(
    "INSERT INTO explainsec_investigations(tenant_id, case_id, title) VALUES ($1,$2,'cross')",
    [tenantB, created.case_id]
  ));
  await service.create(context, "evidence", {
    incident_id: incident.incident_id, storage_uri: "gs://controlled/reference",
  });
  await service.create(context, "tasks", { case_id: created.case_id, title: "Task" });
  await service.create(context, "timeline", {
    case_id: created.case_id, event_type: "CREATED", summary: "Case created",
  });
  await assert.rejects(() => service.update(
    context, "timeline", "00000000-0000-4000-8000-000000000000", { summary: "rewrite" }
  ), /append-only/);
  assert.ok(investigation.investigation_id);
  await assert.rejects(() => admin.query(
    "INSERT INTO explainsec_incidents(tenant_id, case_id, title) VALUES ($1,$2,'cross')", [tenantB, created.case_id]
  ));
  await assert.rejects(() => service.update(context, "incidents", incident.incident_id, { status: "NOT_A_STATUS" }));

  const catalog = await admin.query(`
    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
      count(p.policyname)::int AS policies
    FROM pg_class c LEFT JOIN pg_policies p ON p.tablename = c.relname
    WHERE c.relname IN ('explainsec_cases','explainsec_incidents','explainsec_investigations',
      'explainsec_evidence_metadata','explainsec_tasks','explainsec_timeline_entries')
    GROUP BY c.relname,c.relrowsecurity,c.relforcerowsecurity
  `);
  assert.equal(catalog.rowCount, 6);
  catalog.rows.forEach((row) => {
    assert.equal(row.relrowsecurity, true);
    assert.equal(row.relforcerowsecurity, true);
    assert.equal(row.policies, 4);
  });
});
