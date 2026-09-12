DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_relationship_status') THEN
    CREATE TYPE explainsec_relationship_status AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_portfolio_status') THEN
    CREATE TYPE explainsec_portfolio_status AS ENUM ('ACTIVE', 'SUSPENDED', 'ARCHIVED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_grant_status') THEN
    CREATE TYPE explainsec_grant_status AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_mssp_role') THEN
    CREATE TYPE explainsec_mssp_role AS ENUM ('MSSP_ANALYST', 'MSSP_MANAGER', 'MSSP_AUDITOR');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS explainsec_vendor_relationships (
  relationship_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  customer_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  status explainsec_relationship_status NOT NULL DEFAULT 'PENDING',
  allow_future_tenants BOOLEAN NOT NULL DEFAULT false,
  effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_until TIMESTAMPTZ,
  created_by UUID REFERENCES explainsec_users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (vendor_organization_id, customer_organization_id),
  CHECK (vendor_organization_id <> customer_organization_id),
  CHECK (effective_until IS NULL OR effective_until > effective_from)
);
CREATE TABLE IF NOT EXISTS explainsec_portfolios (
  portfolio_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  name TEXT NOT NULL,
  status explainsec_portfolio_status NOT NULL DEFAULT 'ACTIVE',
  created_by UUID REFERENCES explainsec_users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (vendor_organization_id, name)
);
CREATE TABLE IF NOT EXISTS explainsec_portfolio_organization_grants (
  grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  portfolio_id UUID NOT NULL REFERENCES explainsec_portfolios(portfolio_id) ON DELETE CASCADE,
  vendor_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  customer_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  relationship_id UUID NOT NULL REFERENCES explainsec_vendor_relationships(relationship_id),
  status explainsec_grant_status NOT NULL DEFAULT 'ACTIVE',
  effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (portfolio_id, customer_organization_id),
  CHECK (effective_until IS NULL OR effective_until > effective_from)
);
CREATE TABLE IF NOT EXISTS explainsec_portfolio_tenant_grants (
  grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  portfolio_id UUID NOT NULL REFERENCES explainsec_portfolios(portfolio_id) ON DELETE CASCADE,
  vendor_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  customer_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  tenant_id UUID NOT NULL,
  relationship_id UUID NOT NULL REFERENCES explainsec_vendor_relationships(relationship_id),
  status explainsec_grant_status NOT NULL DEFAULT 'ACTIVE',
  effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (portfolio_id, tenant_id),
  FOREIGN KEY (tenant_id, customer_organization_id)
    REFERENCES explainsec_tenants(tenant_id, organization_id),
  CHECK (effective_until IS NULL OR effective_until > effective_from)
);
CREATE TABLE IF NOT EXISTS explainsec_mssp_memberships (
  mssp_membership_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES explainsec_users(user_id),
  vendor_organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  portfolio_id UUID NOT NULL REFERENCES explainsec_portfolios(portfolio_id) ON DELETE CASCADE,
  role explainsec_mssp_role NOT NULL,
  status explainsec_membership_status NOT NULL DEFAULT 'PENDING',
  effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (effective_until IS NULL OR effective_until > effective_from),
  UNIQUE (user_id, portfolio_id, role)
);

CREATE OR REPLACE FUNCTION explainsec_mt5_validate_links() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE p_vendor UUID; rel_vendor UUID; rel_customer UUID; tenant_customer UUID;
DECLARE vendor_type explainsec_organization_type; customer_type explainsec_organization_type;
BEGIN
  IF TG_TABLE_NAME = 'explainsec_vendor_relationships' THEN
    IF TG_OP = 'UPDATE' AND
       (NEW.vendor_organization_id <> OLD.vendor_organization_id OR
        NEW.customer_organization_id <> OLD.customer_organization_id) AND
       (EXISTS (SELECT 1 FROM explainsec_portfolio_organization_grants WHERE relationship_id = OLD.relationship_id)
        OR EXISTS (SELECT 1 FROM explainsec_portfolio_tenant_grants WHERE relationship_id = OLD.relationship_id)) THEN
      RAISE EXCEPTION 'cannot change relationship parties while grants exist';
    END IF;
    SELECT organization_type INTO vendor_type FROM explainsec_organizations WHERE organization_id = NEW.vendor_organization_id;
    SELECT organization_type INTO customer_type FROM explainsec_organizations WHERE organization_id = NEW.customer_organization_id;
    IF vendor_type <> 'VENDOR' OR customer_type <> 'CUSTOMER' OR
       NEW.vendor_organization_id = NEW.customer_organization_id THEN
      RAISE EXCEPTION 'relationship requires distinct VENDOR and CUSTOMER organizations';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'explainsec_portfolios' THEN
    IF TG_OP = 'UPDATE' AND NEW.vendor_organization_id <> OLD.vendor_organization_id AND
       (EXISTS (SELECT 1 FROM explainsec_portfolio_organization_grants WHERE portfolio_id = OLD.portfolio_id)
        OR EXISTS (SELECT 1 FROM explainsec_portfolio_tenant_grants WHERE portfolio_id = OLD.portfolio_id)) THEN
      RAISE EXCEPTION 'cannot change portfolio vendor while grants exist';
    END IF;
    SELECT organization_type INTO vendor_type FROM explainsec_organizations WHERE organization_id = NEW.vendor_organization_id;
    IF vendor_type <> 'VENDOR' THEN RAISE EXCEPTION 'portfolio owner must be a VENDOR organization'; END IF;
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'explainsec_portfolio_organization_grants' THEN
    SELECT vendor_organization_id INTO p_vendor FROM explainsec_portfolios WHERE portfolio_id = NEW.portfolio_id;
    SELECT vendor_organization_id, customer_organization_id INTO rel_vendor, rel_customer
      FROM explainsec_vendor_relationships WHERE relationship_id = NEW.relationship_id;
    IF p_vendor IS NULL OR p_vendor <> NEW.vendor_organization_id OR
       rel_vendor <> NEW.vendor_organization_id OR rel_customer <> NEW.customer_organization_id THEN
      RAISE EXCEPTION 'portfolio organization grant crosses vendor or relationship';
    END IF;
  ELSIF TG_TABLE_NAME = 'explainsec_portfolio_tenant_grants' THEN
    SELECT vendor_organization_id INTO p_vendor FROM explainsec_portfolios WHERE portfolio_id = NEW.portfolio_id;
    SELECT vendor_organization_id, customer_organization_id INTO rel_vendor, rel_customer
      FROM explainsec_vendor_relationships WHERE relationship_id = NEW.relationship_id;
    SELECT organization_id INTO tenant_customer FROM explainsec_tenants WHERE tenant_id = NEW.tenant_id;
    IF p_vendor IS NULL OR p_vendor <> NEW.vendor_organization_id OR
       rel_vendor <> NEW.vendor_organization_id OR rel_customer <> NEW.customer_organization_id OR
       tenant_customer <> NEW.customer_organization_id THEN
      RAISE EXCEPTION 'portfolio tenant grant crosses vendor, relationship, or tenant organization';
    END IF;
  ELSE
    SELECT vendor_organization_id INTO p_vendor FROM explainsec_portfolios WHERE portfolio_id = NEW.portfolio_id;
    IF p_vendor IS NULL OR p_vendor <> NEW.vendor_organization_id THEN
      RAISE EXCEPTION 'MSSP membership is not scoped to portfolio vendor';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS explainsec_mt5_relationship_types ON explainsec_vendor_relationships;
CREATE TRIGGER explainsec_mt5_relationship_types BEFORE INSERT OR UPDATE ON explainsec_vendor_relationships
FOR EACH ROW EXECUTE FUNCTION explainsec_mt5_validate_links();
DROP TRIGGER IF EXISTS explainsec_mt5_portfolio_owner ON explainsec_portfolios;
CREATE TRIGGER explainsec_mt5_portfolio_owner BEFORE INSERT OR UPDATE ON explainsec_portfolios
FOR EACH ROW EXECUTE FUNCTION explainsec_mt5_validate_links();
DROP TRIGGER IF EXISTS explainsec_mt5_org_grant_links ON explainsec_portfolio_organization_grants;
CREATE TRIGGER explainsec_mt5_org_grant_links BEFORE INSERT OR UPDATE ON explainsec_portfolio_organization_grants
FOR EACH ROW EXECUTE FUNCTION explainsec_mt5_validate_links();
DROP TRIGGER IF EXISTS explainsec_mt5_tenant_grant_links ON explainsec_portfolio_tenant_grants;
CREATE TRIGGER explainsec_mt5_tenant_grant_links BEFORE INSERT OR UPDATE ON explainsec_portfolio_tenant_grants
FOR EACH ROW EXECUTE FUNCTION explainsec_mt5_validate_links();
DROP TRIGGER IF EXISTS explainsec_mt5_membership_links ON explainsec_mssp_memberships;
CREATE TRIGGER explainsec_mt5_membership_links BEFORE INSERT OR UPDATE ON explainsec_mssp_memberships
FOR EACH ROW EXECUTE FUNCTION explainsec_mt5_validate_links();

CREATE TABLE IF NOT EXISTS explainsec_authorization_audit (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES explainsec_users(user_id),
  vendor_organization_id UUID REFERENCES explainsec_organizations(organization_id),
  portfolio_id UUID REFERENCES explainsec_portfolios(portfolio_id),
  customer_organization_id UUID REFERENCES explainsec_organizations(organization_id),
  tenant_id UUID REFERENCES explainsec_tenants(tenant_id),
  action TEXT NOT NULL, allowed BOOLEAN NOT NULL, reason TEXT NOT NULL,
  request_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS explainsec_mt5_tenant_grants_lookup
  ON explainsec_portfolio_tenant_grants (tenant_id, portfolio_id, status);
CREATE INDEX IF NOT EXISTS explainsec_mt5_memberships_lookup
  ON explainsec_mssp_memberships (user_id, portfolio_id, status);

-- These tables contain authorization metadata, not operational tenant data. They
-- are not granted to arbitrary clients; operational resources retain MT-1/MT-4 RLS.
ALTER TABLE explainsec_authorization_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE explainsec_authorization_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY explainsec_authorization_audit_select_deny ON explainsec_authorization_audit
  FOR SELECT USING (false);
CREATE POLICY explainsec_authorization_audit_insert ON explainsec_authorization_audit
  FOR INSERT WITH CHECK (true);
