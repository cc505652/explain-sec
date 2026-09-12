const test = require("node:test");
const assert = require("node:assert/strict");
const { getAdminPool, closePools } = require("../db/pool");
const { getRuntimePool } = require("../db/pool");
const { resolveSecurityContext } = require("../securityContext");

const configured = Boolean(
  process.env.EXPLAINSEC_PG_RUNTIME_URL && process.env.EXPLAINSEC_PG_ADMIN_URL
);

test("MT-5 MSSP relationships and grants enforce vendor boundaries", { skip: !configured }, async (t) => {
  const db = getAdminPool();
  const orgs = await db.query(`
    INSERT INTO explainsec_organizations(organization_type, name)
    VALUES ('VENDOR','MT5 vendor'), ('CUSTOMER','MT5 customer')
    RETURNING organization_id, organization_type
  `);
  const vendor = orgs.rows.find((row) => row.organization_type === "VENDOR").organization_id;
  const customer = orgs.rows.find((row) => row.organization_type === "CUSTOMER").organization_id;
  const relationship = await db.query(`
    INSERT INTO explainsec_vendor_relationships(vendor_organization_id, customer_organization_id, status)
    VALUES ($1,$2,'ACTIVE') RETURNING relationship_id
  `, [vendor, customer]);
  const portfolio = await db.query(`
    INSERT INTO explainsec_portfolios(vendor_organization_id, name) VALUES ($1,'Alpha')
    RETURNING portfolio_id
  `, [vendor]);
  const oldTenant = await db.query(
    "INSERT INTO explainsec_tenants(organization_id,name,slug,status,created_at) VALUES ($1,'Old','mt5-old','ACTIVE',now()-interval '1 minute') RETURNING tenant_id",
    [customer]
  );
  const grant = await db.query(`
    INSERT INTO explainsec_portfolio_organization_grants
      (portfolio_id,vendor_organization_id,customer_organization_id,relationship_id)
    VALUES ($1,$2,$3,$4) RETURNING grant_id
  `, [portfolio.rows[0].portfolio_id, vendor, customer, relationship.rows[0].relationship_id]);
  const futureTenant = await db.query(
    "INSERT INTO explainsec_tenants(organization_id,name,slug,status) VALUES ($1,'Future','mt5-future','ACTIVE') RETURNING tenant_id",
    [customer]
  );
  const user = await db.query("INSERT INTO explainsec_users(display_name) VALUES ('MT5 analyst') RETURNING user_id");
  await db.query(
    "INSERT INTO explainsec_identities(user_id,provider_type,provider_subject,verified_at) VALUES ($1,'firebase','mt5-user',now())",
    [user.rows[0].user_id]
  );
  await db.query(
    "INSERT INTO explainsec_mssp_memberships(user_id,vendor_organization_id,portfolio_id,role,status) VALUES ($1,$2,$3,'MSSP_ANALYST','ACTIVE')",
    [user.rows[0].user_id, vendor, portfolio.rows[0].portfolio_id]
  );
  t.after(async () => {
    await db.query("TRUNCATE explainsec_mssp_memberships, explainsec_portfolio_tenant_grants, explainsec_portfolio_organization_grants, explainsec_portfolios, explainsec_vendor_relationships, explainsec_organizations CASCADE");
    await closePools();
  });
  await assert.rejects(() => db.query(`
    INSERT INTO explainsec_portfolio_organization_grants
      (portfolio_id,vendor_organization_id,customer_organization_id,relationship_id)
    VALUES ($1,$2,$2,$3)
  `, [portfolio.rows[0].portfolio_id, vendor, relationship.rows[0].relationship_id]));
  const context = await resolveSecurityContext(
    "mt5-user",
    { vendorOrganizationId: vendor, portfolioId: portfolio.rows[0].portfolio_id },
    getRuntimePool()
  );
  assert.deepEqual(context.effectiveTenantIds, [oldTenant.rows[0].tenant_id]);
  assert.equal(context.effectiveTenantIds.includes(futureTenant.rows[0].tenant_id), false);
  assert.equal(context.msspMemberships[0].portfolioId, portfolio.rows[0].portfolio_id);
  assert.equal(grant.rowCount, 1);
});
