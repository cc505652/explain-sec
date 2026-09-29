const fs = require("node:fs/promises");
const path = require("node:path");
const { getAdminPool, closePools } = require("../db/pool");
const { assertRuntimeRoleNoBypassRls, grantRuntimePrivileges } = require("../db/runtimeRole");

async function migrate() {
  const pool = getAdminPool();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS explainsec_schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  const migrations = [
    ["001_mt1_foundation", "001_mt1_foundation.sql"],
    ["002_mt4_operational_resources", "002_mt4_operational_resources.sql"],
    ["003_mt5_mssp_portfolio_authorization", "003_mt5_mssp_portfolio_authorization.sql"],
    ["004_authorization_audit_boundary", "004_authorization_audit_boundary.sql"],
  ];
  for (const [version, filename] of migrations) {
    const existing = await pool.query(
      "SELECT 1 FROM explainsec_schema_migrations WHERE version = $1", [version]
    );
    if (existing.rowCount !== 0) continue;
    const sql = await fs.readFile(path.join(__dirname, "..", "db", "migrations", filename), "utf8");
    await pool.query("BEGIN");
    try {
      await pool.query(sql);
      await pool.query("INSERT INTO explainsec_schema_migrations(version) VALUES ($1)", [version]);
      await pool.query("COMMIT");
    } catch (error) {
      await pool.query("ROLLBACK").catch(() => {});
      throw error;
    }
  }
  await grantRuntimePrivileges(pool);
  await assertRuntimeRoleNoBypassRls();
  console.log("MT-1 through MT-5 migrations are applied; runtime role security attributes are valid.");
}

migrate()
  .catch((error) => {
    console.error(`[MT-1] migration failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(closePools);
