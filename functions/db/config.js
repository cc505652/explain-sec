const DEFAULT_RUNTIME_ROLE = "explainsec_runtime";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sslConfig() {
  if (process.env.EXPLAINSEC_PG_SSL !== "true") return false;
  const config = {
    rejectUnauthorized: process.env.EXPLAINSEC_PG_SSL_REJECT_UNAUTHORIZED !== "false",
  };
  if (process.env.EXPLAINSEC_PG_SSL_SERVERNAME) {
    config.servername = process.env.EXPLAINSEC_PG_SSL_SERVERNAME;
  }
  return config;
}

function connectionConfig(urlName) {
  return {
    connectionString: required(urlName),
    max: Number(process.env.EXPLAINSEC_PG_POOL_MAX || 10),
    idleTimeoutMillis: Number(process.env.EXPLAINSEC_PG_IDLE_TIMEOUT_MS || 30000),
    connectionTimeoutMillis: Number(process.env.EXPLAINSEC_PG_CONNECTION_TIMEOUT_MS || 5000),
    ssl: sslConfig(),
  };
}

function runtimeRole() {
  return process.env.EXPLAINSEC_PG_RUNTIME_ROLE || DEFAULT_RUNTIME_ROLE;
}

module.exports = {
  adminConfig: () => connectionConfig("EXPLAINSEC_PG_ADMIN_URL"),
  runtimeConfig: () => connectionConfig("EXPLAINSEC_PG_RUNTIME_URL"),
  runtimeRole,
};
