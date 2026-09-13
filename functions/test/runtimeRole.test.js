const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { grantRuntimePrivileges } = require("../db/runtimeRole");

test("runtime privilege bootstrap does not modify schema ACLs", async () => {
  const queries = [];
  const pool = {
    query: async (text) => {
      queries.push(text);
      return { rowCount: 0, rows: [] };
    },
  };

  await grantRuntimePrivileges(pool, "explainsec_runtime");

  assert.equal(
    queries.some((query) => /(?:GRANT|REVOKE).*ON SCHEMA/i.test(query)),
    false
  );
  assert.equal(
    queries.some((query) => /GRANT SELECT, INSERT, UPDATE, DELETE/i.test(query)),
    true
  );
  assert.equal(
    queries.some((query) => /REVOKE ALL ON explainsec_authorization_audit/i.test(query)),
    true
  );
  assert.equal(
    queries.some((query) => /GRANT EXECUTE ON FUNCTION fn_record_authorization_decision/i.test(query)),
    true
  );
});

test("migration 004 leaves schema ACL bootstrap to deployment authority", () => {
  const migration = fs.readFileSync(
    path.join(__dirname, "..", "db", "migrations", "004_authorization_audit_boundary.sql"),
    "utf8"
  );

  assert.equal(/(?:GRANT|REVOKE)[\s\S]{0,80}ON SCHEMA/i.test(migration), false);
  assert.match(migration, /GRANT INSERT ON explainsec_authorization_audit TO explainsec_audit_writer/);
  assert.match(migration, /GRANT SELECT ON[\s\S]+TO explainsec_audit_writer/);
  assert.match(migration, /CREATE INDEX IF NOT EXISTS/);
});
