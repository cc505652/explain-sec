"use strict";

const { getRuntimePool } = require("./db/pool");

const ACTIVE = ["ACTIVE"];

function createVendorPortfolioRepository(pool = getRuntimePool()) {
  return {
    async resolveScope(userId, vendorOrganizationId, portfolioId, tenantId) {
      const result = await pool.query(`
        SELECT mm.mssp_membership_id, mm.role, p.portfolio_id, p.vendor_organization_id,
               r.customer_organization_id, tg.tenant_id
        FROM explainsec_mssp_memberships mm
        JOIN explainsec_portfolios p ON p.portfolio_id = mm.portfolio_id AND p.status = 'ACTIVE'
        JOIN (
          SELECT portfolio_id, tenant_id, relationship_id, status, effective_from, effective_until
            FROM explainsec_portfolio_tenant_grants
          UNION
          SELECT og.portfolio_id, t.tenant_id, og.relationship_id, og.status,
                 og.effective_from, og.effective_until
            FROM explainsec_portfolio_organization_grants og
            JOIN explainsec_vendor_relationships orr ON orr.relationship_id = og.relationship_id
            JOIN explainsec_tenants t ON t.organization_id = og.customer_organization_id
             AND (orr.allow_future_tenants = true OR t.created_at <= og.created_at)
        ) tg ON tg.portfolio_id = p.portfolio_id
        JOIN explainsec_vendor_relationships r ON r.relationship_id = tg.relationship_id
        WHERE mm.user_id = $1 AND mm.status = 'ACTIVE'
          AND mm.effective_from <= now() AND (mm.effective_until IS NULL OR mm.effective_until > now())
          AND r.status = 'ACTIVE' AND r.effective_from <= now()
          AND (r.effective_until IS NULL OR r.effective_until > now())
          AND tg.status = 'ACTIVE' AND tg.effective_from <= now()
          AND (tg.effective_until IS NULL OR tg.effective_until > now())
          AND ($3::uuid IS NULL OR p.vendor_organization_id = $3)
          AND ($4::uuid IS NULL OR p.portfolio_id = $4)
          AND ($5::uuid IS NULL OR tg.tenant_id = $5)
      `, [userId, ACTIVE, vendorOrganizationId || null, portfolioId || null, tenantId || null]);
      return result.rows;
    },
    async audit(envelope, executor = pool) {
      if (!envelope || typeof envelope !== "object") {
        throw new Error("Authorization audit envelope is required");
      }
      const result = await executor.query(`
        SELECT fn_record_authorization_decision(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
        ) AS audit_id
      `, [
        envelope.scopeType, envelope.userId, envelope.membershipId,
        envelope.organizationId, envelope.vendorOrganizationId,
        envelope.customerOrganizationId, envelope.portfolioId,
        envelope.relationshipId, envelope.action, envelope.permission,
        envelope.allowed, envelope.reason, envelope.policyId,
        envelope.resourceId, envelope.resourceType, envelope.requestId,
        envelope.decisionVersion,
      ]);
      return result.rows[0];
    },
  };
}

module.exports = { createVendorPortfolioRepository };
