const { getRuntimePool } = require("./pool");
const { runtimeRole } = require("./config");

function quoteIdentifier(identifier) {
  return `"${identifier.replace(/"/g, "\"\"")}"`;
}

async function assertRuntimeRoleNoBypassRls(pool = getRuntimePool()) {
  const result = await pool.query(
    "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = $1",
    [runtimeRole()]
  );
  if (result.rowCount !== 1) {
    throw new Error(`Configured runtime role does not exist: ${runtimeRole()}`);
  }
  const role = result.rows[0];
  if (role.rolcanlogin !== true || role.rolsuper !== false ||
      role.rolcreatedb !== false || role.rolcreaterole !== false ||
      role.rolbypassrls !== false) {
    throw new Error(
      `Runtime role must be LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS: ${runtimeRole()}`
    );
  }
  return role;
}

async function grantRuntimePrivileges(pool, role = runtimeRole()) {
  const quotedRole = quoteIdentifier(role);
  await pool.query(`GRANT USAGE ON SCHEMA public TO ${quotedRole}`);
  await pool.query(`
    GRANT SELECT, INSERT, UPDATE, DELETE
    ON explainsec_users, explainsec_identities, explainsec_organizations,
       explainsec_tenants, explainsec_memberships, explainsec_mt1_rls_probe,
       explainsec_cases, explainsec_incidents, explainsec_investigations,
       explainsec_evidence_metadata, explainsec_tasks, explainsec_timeline_entries,
       explainsec_vendor_relationships, explainsec_portfolios,
       explainsec_portfolio_organization_grants, explainsec_portfolio_tenant_grants,
       explainsec_mssp_memberships
    TO ${quotedRole}
  `);
  await pool.query("REVOKE ALL ON explainsec_authorization_audit FROM " + quotedRole);
  await pool.query(`
    GRANT EXECUTE ON FUNCTION fn_record_authorization_decision(
      TEXT, UUID, UUID, UUID, UUID, UUID, UUID, UUID,
      TEXT, TEXT, BOOLEAN, TEXT, TEXT, UUID, TEXT, TEXT, TEXT
    ) TO ${quotedRole}
  `);
}

module.exports = { assertRuntimeRoleNoBypassRls, grantRuntimePrivileges };
