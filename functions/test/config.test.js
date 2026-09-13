const test = require("node:test");
const assert = require("node:assert/strict");
const { adminConfig } = require("../db/config");

const originalEnvironment = {
  adminUrl: process.env.EXPLAINSEC_PG_ADMIN_URL,
  ssl: process.env.EXPLAINSEC_PG_SSL,
  rejectUnauthorized: process.env.EXPLAINSEC_PG_SSL_REJECT_UNAUTHORIZED,
  servername: process.env.EXPLAINSEC_PG_SSL_SERVERNAME,
};

function restoreEnvironment() {
  const values = {
    EXPLAINSEC_PG_ADMIN_URL: originalEnvironment.adminUrl,
    EXPLAINSEC_PG_SSL: originalEnvironment.ssl,
    EXPLAINSEC_PG_SSL_REJECT_UNAUTHORIZED: originalEnvironment.rejectUnauthorized,
    EXPLAINSEC_PG_SSL_SERVERNAME: originalEnvironment.servername,
  };
  for (const [name, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

function configureSsl({ enabled, rejectUnauthorized, servername }) {
  process.env.EXPLAINSEC_PG_ADMIN_URL = "postgresql://test-user@localhost:5432/explainsec";
  process.env.EXPLAINSEC_PG_SSL = enabled ? "true" : "false";
  if (rejectUnauthorized === undefined) {
    delete process.env.EXPLAINSEC_PG_SSL_REJECT_UNAUTHORIZED;
  } else {
    process.env.EXPLAINSEC_PG_SSL_REJECT_UNAUTHORIZED = rejectUnauthorized;
  }
  if (servername === undefined) delete process.env.EXPLAINSEC_PG_SSL_SERVERNAME;
  else process.env.EXPLAINSEC_PG_SSL_SERVERNAME = servername;
}

test.after(restoreEnvironment);

test("SSL disabled returns false", () => {
  configureSsl({ enabled: false, rejectUnauthorized: "true" });
  assert.equal(adminConfig().ssl, false);
});

test("SSL enabled defaults to certificate verification", () => {
  configureSsl({ enabled: true, rejectUnauthorized: "true" });
  assert.deepEqual(adminConfig().ssl, { rejectUnauthorized: true });
});

test("SSL servername is preserved when configured", () => {
  configureSsl({
    enabled: true,
    rejectUnauthorized: "true",
    servername: "cloudsql.example.test",
  });
  assert.deepEqual(adminConfig().ssl, {
    rejectUnauthorized: true,
    servername: "cloudsql.example.test",
  });
});

test("TLS configuration does not replace the connection-string host", () => {
  const connectionString = "postgresql://test-user@db.internal:5432/explainsec?sslmode=require";
  configureSsl({
    enabled: true,
    rejectUnauthorized: "true",
    servername: "cloudsql.example.test",
  });
  process.env.EXPLAINSEC_PG_ADMIN_URL = connectionString;
  const config = adminConfig();
  assert.equal(config.connectionString, connectionString);
  assert.equal(new URL(config.connectionString).hostname, "db.internal");
});

test("explicit false is the only way to disable certificate verification", () => {
  configureSsl({ enabled: true, rejectUnauthorized: undefined });
  assert.equal(adminConfig().ssl.rejectUnauthorized, true);

  configureSsl({ enabled: true, rejectUnauthorized: "false" });
  assert.equal(adminConfig().ssl.rejectUnauthorized, false);
});
