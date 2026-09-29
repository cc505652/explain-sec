const { getRuntimePool } = require("./db/pool");

const ACTIVE_MEMBERSHIP = ["ACTIVE"];
const ROLE_PERMISSIONS = Object.freeze({
  PLATFORM_ADMIN: ["soc:read"],
  ORGANIZATION_OWNER: ["soc:read"],
  ORGANIZATION_ADMIN: ["soc:read"],
  ORGANIZATION_MEMBER: ["soc:read"],
  TENANT_ADMIN: ["soc:read", "soc:write"],
  VENDOR_MEMBER: ["soc:read"],
  MSSP_ANALYST: ["soc:read"],
  SOC_MANAGER: ["soc:read", "soc:write"],
});

function immutable(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    Object.keys(value).forEach((key) => immutable(value[key]));
  }
  return value;
}

function selectorsOf(selectors = {}) {
  if (selectors.organizationId && selectors.organization_id &&
      selectors.organizationId !== selectors.organization_id) {
    throw new Error("Conflicting organization selectors");
  }
  if (selectors.tenantId && selectors.tenant_id && selectors.tenantId !== selectors.tenant_id) {
    throw new Error("Conflicting tenant selectors");
  }
  const organizationId = selectors.organizationId || selectors.organization_id || null;
  const tenantId = selectors.tenantId || selectors.tenant_id || null;
  const vendorOrganizationId = selectors.vendorOrganizationId || selectors.vendor_organization_id || null;
  const portfolioId = selectors.portfolioId || selectors.portfolio_id || null;
  if (!organizationId && !tenantId && !vendorOrganizationId && !portfolioId) {
    throw new Error("Security context requires an organization, tenant, vendor, or portfolio selector");
  }
  if (tenantId && !organizationId) {
    throw new Error("tenantId requires an organizationId selector");
  }
  return {
    organizationId,
    tenantId,
    vendorOrganizationId,
    portfolioId,
  };
}

/**
 * Resolve authorization exclusively from PostgreSQL. `verifiedFirebaseUid` must
 * already have been verified by Firebase Admin; it is never taken from a body.
 */
async function resolveSecurityContext(
  verifiedFirebaseUid,
  selectors,
  pool = getRuntimePool(),
  metadata = {}
) {
  if (typeof verifiedFirebaseUid !== "string" || !verifiedFirebaseUid.trim()) {
    throw new Error("A verified Firebase UID is required");
  }
  const { organizationId, tenantId, vendorOrganizationId, portfolioId } = selectorsOf(selectors);
  const result = await pool.query(`
    SELECT u.user_id, u.display_name, u.email, i.provider_subject,
           m.membership_id, m.membership_type, m.role,
           m.organization_id, m.tenant_id,
           o.status AS organization_status, t.status AS tenant_status
      FROM explainsec_identities i
      JOIN explainsec_users u ON u.user_id = i.user_id
      JOIN explainsec_memberships m ON m.user_id = u.user_id
      LEFT JOIN explainsec_organizations o ON o.organization_id = m.organization_id
      LEFT JOIN explainsec_tenants t ON t.tenant_id = m.tenant_id
     WHERE i.provider_type = 'firebase'
       AND i.provider_subject = $1
       AND i.status = 'ACTIVE'
       AND i.verified_at IS NOT NULL
       AND u.status = 'ACTIVE'
       AND m.status = ANY($2::explainsec_membership_status[])
       AND m.effective_from <= now()
       AND (m.effective_until IS NULL OR m.effective_until > now())
       AND (m.organization_id = $3::uuid OR m.organization_id IS NULL)
       AND (m.tenant_id = $4::uuid OR m.tenant_id IS NULL)
       AND (o.organization_id IS NULL OR o.status = 'ACTIVE')
       AND (t.tenant_id IS NULL OR t.status = 'ACTIVE')
     ORDER BY CASE WHEN m.tenant_id IS NOT NULL THEN 0
                  WHEN m.organization_id IS NOT NULL THEN 1 ELSE 2 END,
              m.role
  `, [verifiedFirebaseUid, ACTIVE_MEMBERSHIP, organizationId, tenantId]);
  const mssp = await pool.query(`
    SELECT mm.mssp_membership_id, mm.role, p.portfolio_id, p.vendor_organization_id,
           u.user_id, u.display_name, u.email,
           r.customer_organization_id, tg.tenant_id
      FROM explainsec_mssp_memberships mm
      JOIN explainsec_users u ON u.user_id = mm.user_id AND u.status = 'ACTIVE'
      JOIN explainsec_portfolios p ON p.portfolio_id = mm.portfolio_id AND p.status = 'ACTIVE'
      JOIN (
        SELECT tg.portfolio_id, tg.tenant_id, tg.relationship_id, tg.status,
               tg.effective_from, tg.effective_until
          FROM explainsec_portfolio_tenant_grants tg
        UNION
        SELECT og.portfolio_id, t.tenant_id, og.relationship_id, og.status,
               og.effective_from, og.effective_until
          FROM explainsec_portfolio_organization_grants og
          JOIN explainsec_vendor_relationships orr ON orr.relationship_id = og.relationship_id
          JOIN explainsec_tenants t ON t.organization_id = og.customer_organization_id
           AND (orr.allow_future_tenants = true OR t.created_at <= og.created_at)
      ) tg ON tg.portfolio_id = p.portfolio_id
      JOIN explainsec_vendor_relationships r ON r.relationship_id = tg.relationship_id
      JOIN explainsec_tenants t ON t.tenant_id = tg.tenant_id AND t.status = 'ACTIVE'
     WHERE mm.user_id = (SELECT user_id FROM explainsec_identities
                          WHERE provider_type = 'firebase' AND provider_subject = $1
                            AND status = 'ACTIVE' AND verified_at IS NOT NULL)
       AND mm.status = 'ACTIVE' AND mm.effective_from <= now()
       AND (mm.effective_until IS NULL OR mm.effective_until > now())
       AND r.status = 'ACTIVE' AND r.effective_from <= now()
       AND (r.effective_until IS NULL OR r.effective_until > now())
       AND tg.status = 'ACTIVE' AND tg.effective_from <= now()
       AND (tg.effective_until IS NULL OR tg.effective_until > now())
       AND ($2::uuid IS NULL OR r.vendor_organization_id = $2)
       AND ($3::uuid IS NULL OR p.portfolio_id = $3)
       AND ($4::uuid IS NULL OR tg.tenant_id = $4)
       AND ($5::uuid IS NULL OR r.customer_organization_id = $5)
  `, [verifiedFirebaseUid, vendorOrganizationId, portfolioId, tenantId, organizationId]);
  if (!result.rowCount && !mssp.rowCount) {
    throw new Error("Unauthorized: no active matching identity or membership");
  }

  // A tenant selector must be authorized by a tenant membership. Organization
  // memberships intentionally do not grant access to a tenant.
  const scoped = result.rows.filter((row) =>
    tenantId ? row.tenant_id === tenantId : row.tenant_id === null
  );
  if (!scoped.length && !mssp.rowCount) throw new Error("Forbidden: membership is not valid for requested scope");
  const roles = [...new Set(scoped.map((row) => row.role).concat(
    mssp.rows.map((row) => row.role === "MSSP_MANAGER" ? "SOC_MANAGER" :
      row.role === "MSSP_AUDITOR" ? "MSSP_ANALYST" : "MSSP_ANALYST")
  ))];
  const permissions = [...new Set(roles.flatMap((role) => ROLE_PERMISSIONS[role] || []))];
  const first = scoped[0] || mssp.rows[0];
  const effectiveTenantIds = [...new Set(mssp.rows.map((row) => row.tenant_id)
    .concat(tenantId ? [tenantId] : []))];
  return immutable({
    requestId: metadata.requestId || null,
    uid: verifiedFirebaseUid,
    firebaseUid: verifiedFirebaseUid,
    userId: first.user_id,
    displayName: first.display_name,
    email: first.email,
    sessionId: metadata.sessionId || null,
    authenticationStrength: metadata.authenticationStrength || "firebase_id_token",
    userStatus: "ACTIVE",
    organizationId: organizationId || first.organization_id,
    tenantId: tenantId || null,
    vendorOrganizationId: mssp.rows[0] && mssp.rows[0].vendor_organization_id || vendorOrganizationId || null,
    portfolioId: mssp.rows[0] && mssp.rows[0].portfolio_id || portfolioId || null,
    effectiveTenantIds: Object.freeze(effectiveTenantIds),
    msspMemberships: Object.freeze(mssp.rows.map((row) => Object.freeze({
      membershipId: row.mssp_membership_id,
      role: row.role,
      vendorOrganizationId: row.vendor_organization_id,
      portfolioId: row.portfolio_id,
      customerOrganizationId: row.customer_organization_id,
      tenantId: row.tenant_id,
    }))),
    organizationStatus: first.organization_status || null,
    tenantStatus: first.tenant_status || null,
    activeMembershipId: first.membership_id,
    roles: Object.freeze(roles),
    effectiveRoles: Object.freeze(roles),
    role: roles[0],
    permissions: Object.freeze(permissions),
    effectivePermissions: Object.freeze(permissions),
    memberships: Object.freeze(scoped.map((row) => Object.freeze({
      membershipId: row.membership_id,
      type: row.membership_type,
      role: row.role,
      organizationId: row.organization_id,
      tenantId: row.tenant_id,
    }))),
  });
}

module.exports = {
  resolveSecurityContext,
  resolveAuthoritativeSecurityContext: resolveSecurityContext,
  selectorsOf,
  ROLE_PERMISSIONS,
};
