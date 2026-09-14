const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validateTenantId(tenantId) {
  if (typeof tenantId !== "string" || !UUID_PATTERN.test(tenantId)) {
    throw new Error("A valid tenant ID is required");
  }
  return tenantId;
}

async function setTenantContext(client, tenantId) {
  const validatedTenantId = validateTenantId(tenantId);
  await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [validatedTenantId]);
}

async function withTenantTransaction(pool, tenantId, operation) {
  validateTenantId(tenantId);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await setTenantContext(client, tenantId);
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { validateTenantId, setTenantContext, withTenantTransaction };
