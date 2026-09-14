DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'explainsec_runtime') THEN
    CREATE ROLE explainsec_runtime
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_user_status') THEN
    CREATE TYPE explainsec_user_status AS ENUM ('ACTIVE', 'SUSPENDED', 'DEACTIVATED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_organization_type') THEN
    CREATE TYPE explainsec_organization_type AS ENUM ('CUSTOMER', 'VENDOR', 'INTERNAL');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_organization_status') THEN
    CREATE TYPE explainsec_organization_status AS ENUM ('ACTIVE', 'SUSPENDED', 'DEACTIVATED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_tenant_status') THEN
    CREATE TYPE explainsec_tenant_status AS ENUM (
      'PROVISIONING', 'ACTIVE', 'SUSPENDED', 'ARCHIVED', 'DELETION_PENDING', 'DELETED'
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_membership_type') THEN
    CREATE TYPE explainsec_membership_type AS ENUM ('PLATFORM', 'ORGANIZATION', 'TENANT', 'VENDOR');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_membership_status') THEN
    CREATE TYPE explainsec_membership_status AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_membership_role') THEN
    CREATE TYPE explainsec_membership_role AS ENUM (
      'PLATFORM_ADMIN', 'ORGANIZATION_OWNER', 'ORGANIZATION_ADMIN',
      'ORGANIZATION_MEMBER', 'TENANT_ADMIN', 'VENDOR_MEMBER'
    );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS explainsec_users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  status explainsec_user_status NOT NULL DEFAULT 'ACTIVE',
  display_name TEXT,
  email TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS explainsec_identities (
  identity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES explainsec_users(user_id),
  provider_type TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  status explainsec_user_status NOT NULL DEFAULT 'ACTIVE',
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT explainsec_identity_provider_subject_key UNIQUE (provider_type, provider_subject)
);

CREATE TABLE IF NOT EXISTS explainsec_organizations (
  organization_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_type explainsec_organization_type NOT NULL,
  name TEXT NOT NULL,
  status explainsec_organization_status NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS explainsec_tenants (
  tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES explainsec_organizations(organization_id),
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  status explainsec_tenant_status NOT NULL DEFAULT 'PROVISIONING',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT explainsec_tenant_organization_slug_key UNIQUE (organization_id, slug),
  CONSTRAINT explainsec_tenant_id_organization_key UNIQUE (tenant_id, organization_id)
);

CREATE TABLE IF NOT EXISTS explainsec_memberships (
  membership_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES explainsec_users(user_id),
  organization_id UUID REFERENCES explainsec_organizations(organization_id),
  tenant_id UUID REFERENCES explainsec_tenants(tenant_id),
  membership_type explainsec_membership_type NOT NULL,
  role explainsec_membership_role NOT NULL,
  status explainsec_membership_status NOT NULL DEFAULT 'PENDING',
  effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_until TIMESTAMPTZ,
  granted_by UUID REFERENCES explainsec_users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT explainsec_membership_scope_check CHECK (
    (membership_type = 'PLATFORM' AND organization_id IS NULL AND tenant_id IS NULL)
    OR (membership_type IN ('ORGANIZATION', 'VENDOR') AND organization_id IS NOT NULL AND tenant_id IS NULL)
    OR (membership_type = 'TENANT' AND organization_id IS NOT NULL AND tenant_id IS NOT NULL)
  ),
  CONSTRAINT explainsec_membership_tenant_organization_fk
    FOREIGN KEY (tenant_id, organization_id)
    REFERENCES explainsec_tenants(tenant_id, organization_id),
  CONSTRAINT explainsec_membership_role_scope_check CHECK (
    (role = 'PLATFORM_ADMIN' AND membership_type = 'PLATFORM')
    OR (role IN ('ORGANIZATION_OWNER', 'ORGANIZATION_ADMIN', 'ORGANIZATION_MEMBER', 'VENDOR_MEMBER')
        AND membership_type IN ('ORGANIZATION', 'VENDOR'))
    OR (role = 'TENANT_ADMIN' AND membership_type = 'TENANT')
  ),
  CONSTRAINT explainsec_membership_effective_dates_check CHECK (
    effective_until IS NULL OR effective_until > effective_from
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS explainsec_active_membership_key
  ON explainsec_memberships (user_id, membership_type, organization_id, tenant_id, role)
  WHERE status IN ('PENDING', 'ACTIVE', 'SUSPENDED');

CREATE INDEX IF NOT EXISTS explainsec_memberships_user_scope_idx
  ON explainsec_memberships (user_id, organization_id, tenant_id, status);

CREATE OR REPLACE FUNCTION explainsec_prevent_last_owner_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  active_owner_count INTEGER;
BEGIN
  IF OLD.role = 'ORGANIZATION_OWNER'
     AND OLD.status IN ('PENDING', 'ACTIVE', 'SUSPENDED')
     AND (
       TG_OP = 'DELETE'
       OR NEW.role <> OLD.role
       OR NEW.status NOT IN ('PENDING', 'ACTIVE', 'SUSPENDED')
     ) THEN
    SELECT count(*) INTO active_owner_count
      FROM explainsec_memberships
     WHERE organization_id = OLD.organization_id
       AND role = 'ORGANIZATION_OWNER'
       AND status IN ('PENDING', 'ACTIVE', 'SUSPENDED')
       AND membership_id <> OLD.membership_id;
    IF active_owner_count < 1 THEN
      RAISE EXCEPTION 'organization must retain at least one active owner';
    END IF;
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS explainsec_membership_last_owner_guard ON explainsec_memberships;
CREATE CONSTRAINT TRIGGER explainsec_membership_last_owner_guard
AFTER INSERT OR UPDATE OR DELETE ON explainsec_memberships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION explainsec_prevent_last_owner_change();

CREATE TABLE IF NOT EXISTS explainsec_mt1_rls_probe (
  probe_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES explainsec_tenants(tenant_id),
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE explainsec_mt1_rls_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE explainsec_mt1_rls_probe FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS explainsec_mt1_rls_probe_select ON explainsec_mt1_rls_probe;
CREATE POLICY explainsec_mt1_rls_probe_select ON explainsec_mt1_rls_probe
  FOR SELECT USING (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
  );

DROP POLICY IF EXISTS explainsec_mt1_rls_probe_insert ON explainsec_mt1_rls_probe;
CREATE POLICY explainsec_mt1_rls_probe_insert ON explainsec_mt1_rls_probe
  FOR INSERT WITH CHECK (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
  );

DROP POLICY IF EXISTS explainsec_mt1_rls_probe_update ON explainsec_mt1_rls_probe;
CREATE POLICY explainsec_mt1_rls_probe_update ON explainsec_mt1_rls_probe
  FOR UPDATE
  USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS explainsec_mt1_rls_probe_delete ON explainsec_mt1_rls_probe;
CREATE POLICY explainsec_mt1_rls_probe_delete ON explainsec_mt1_rls_probe
  FOR DELETE USING (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
  );
