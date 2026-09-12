"use strict";

const { createVendorPortfolioRepository } = require("./vendorPortfolioRepository");
const { createAuthorizationAuditEnvelope } = require("./authorizationAudit");

function createVendorPortfolioService(repository = createVendorPortfolioRepository()) {
  return {
    resolve(context, selectors = {}) {
      if (!context || !context.userId) throw new Error("SecurityContext is required");
      // Selectors narrow a server-derived scope; they never add to it.
      return repository.resolveScope(
        context.userId,
        selectors.vendorOrganizationId || context.vendorOrganizationId,
        selectors.portfolioId || context.portfolioId,
        selectors.tenantId || context.tenantId
      );
    },
    audit: (input, executor) => {
      const envelope = createAuthorizationAuditEnvelope(input);
      return repository.audit(envelope, executor);
    },
  };
}

module.exports = { createVendorPortfolioService };
