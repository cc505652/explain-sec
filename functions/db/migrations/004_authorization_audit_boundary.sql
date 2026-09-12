DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'explainsec_audit_writer') THEN
    RAISE EXCEPTION 'Required role explainsec_audit_writer must be pre-created before migration 004';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles
     WHERE rolname = 'explainsec_audit_writer'
       AND rolsuper = false
       AND rolcreatedb = false
       AND rolcreaterole = false
       AND rolbypassrls = false
       AND rolcanlogin = false
  ) THEN
    RAISE EXCEPTION 'explainsec_audit_writer must be NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS';
  END IF;
  IF NOT pg_has_role(current_user, 'explainsec_audit_writer', 'MEMBER') THEN
    RAISE EXCEPTION 'Migration identity must be a member of explainsec_audit_writer for controlled ownership transfer';
  END IF;
END $$;

ALTER TABLE explainsec_authorization_audit
  ADD COLUMN IF NOT EXISTS scope_type TEXT,
  ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES explainsec_organizations(organization_id),
  ADD COLUMN IF NOT EXISTS membership_id UUID REFERENCES explainsec_memberships(membership_id),
  ADD COLUMN IF NOT EXISTS relationship_id UUID REFERENCES explainsec_vendor_relationships(relationship_id),
  ADD COLUMN IF NOT EXISTS permission TEXT,
  ADD COLUMN IF NOT EXISTS policy_id TEXT,
  ADD COLUMN IF NOT EXISTS resource_id UUID,
  ADD COLUMN IF NOT EXISTS resource_type TEXT,
  ADD COLUMN IF NOT EXISTS decision_version TEXT;

ALTER TABLE explainsec_authorization_audit
  ADD CONSTRAINT explainsec_authorization_audit_scope_type_check
    CHECK (scope_type IS NULL OR scope_type IN ('TENANT', 'ORGANIZATION', 'PORTFOLIO', 'PLATFORM')),
  ADD CONSTRAINT explainsec_authorization_audit_resource_pair_check
    CHECK ((resource_id IS NULL) = (resource_type IS NULL)),
  ADD CONSTRAINT explainsec_authorization_audit_text_length_check
    CHECK (
      length(action) BETWEEN 1 AND 128
      AND length(permission) BETWEEN 1 AND 128
      AND length(reason) BETWEEN 1 AND 512
      AND length(policy_id) BETWEEN 1 AND 128
      AND length(decision_version) BETWEEN 1 AND 128
      AND (request_id IS NULL OR length(request_id) BETWEEN 1 AND 256)
    );

CREATE INDEX IF NOT EXISTS explainsec_authorization_audit_tenant_time_idx
  ON explainsec_authorization_audit (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS explainsec_authorization_audit_user_time_idx
  ON explainsec_authorization_audit (user_id, created_at);
CREATE INDEX IF NOT EXISTS explainsec_authorization_audit_request_idx
  ON explainsec_authorization_audit (request_id)
  WHERE request_id IS NOT NULL;

CREATE OR REPLACE FUNCTION explainsec_reject_authorization_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'authorization audit records are append-only';
END;
$$;

DROP TRIGGER IF EXISTS explainsec_authorization_audit_no_update
  ON explainsec_authorization_audit;
CREATE TRIGGER explainsec_authorization_audit_no_update
  BEFORE UPDATE ON explainsec_authorization_audit
  FOR EACH ROW EXECUTE FUNCTION explainsec_reject_authorization_audit_mutation();

DROP TRIGGER IF EXISTS explainsec_authorization_audit_no_delete
  ON explainsec_authorization_audit;
CREATE TRIGGER explainsec_authorization_audit_no_delete
  BEFORE DELETE ON explainsec_authorization_audit
  FOR EACH ROW EXECUTE FUNCTION explainsec_reject_authorization_audit_mutation();

DROP POLICY IF EXISTS explainsec_authorization_audit_insert
  ON explainsec_authorization_audit;
CREATE POLICY explainsec_authorization_audit_insert
  ON explainsec_authorization_audit
  FOR INSERT
  WITH CHECK (
    (scope_type = 'TENANT'
      AND tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
      AND organization_id IS NOT NULL)
    OR (scope_type IN ('ORGANIZATION', 'PORTFOLIO', 'PLATFORM')
      AND tenant_id IS NULL)
  );

DROP POLICY IF EXISTS explainsec_authorization_audit_update
  ON explainsec_authorization_audit;
CREATE POLICY explainsec_authorization_audit_update
  ON explainsec_authorization_audit
  FOR UPDATE USING (false) WITH CHECK (false);

DROP POLICY IF EXISTS explainsec_authorization_audit_delete
  ON explainsec_authorization_audit;
CREATE POLICY explainsec_authorization_audit_delete
  ON explainsec_authorization_audit
  FOR DELETE USING (false);

CREATE OR REPLACE FUNCTION fn_record_authorization_decision(
  p_scope_type TEXT,
  p_user_id UUID,
  p_membership_id UUID,
  p_organization_id UUID,
  p_vendor_organization_id UUID,
  p_customer_organization_id UUID,
  p_portfolio_id UUID,
  p_relationship_id UUID,
  p_action TEXT,
  p_permission TEXT,
  p_allowed BOOLEAN,
  p_reason TEXT,
  p_policy_id TEXT,
  p_resource_id UUID,
  p_resource_type TEXT,
  p_request_id TEXT,
  p_decision_version TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_tenant_id UUID;
  v_identity_subject TEXT;
  v_membership RECORD;
  v_resource_tenant UUID;
  v_expected_permission TEXT;
  v_audit_id UUID;
BEGIN
  IF p_scope_type IS NULL
     OR p_scope_type NOT IN ('TENANT', 'ORGANIZATION', 'PORTFOLIO', 'PLATFORM') THEN
    RAISE EXCEPTION 'Invalid authorization audit scope';
  END IF;
  IF p_user_id IS NULL OR p_action IS NULL OR p_permission IS NULL
     OR p_allowed IS NULL OR p_reason IS NULL OR p_policy_id IS NULL
     OR p_decision_version IS NULL THEN
    RAISE EXCEPTION 'Required authorization audit fields are missing';
  END IF;
  IF length(p_action) NOT BETWEEN 1 AND 128
     OR length(p_permission) NOT BETWEEN 1 AND 128
     OR length(p_reason) NOT BETWEEN 1 AND 512
     OR length(p_policy_id) NOT BETWEEN 1 AND 128
     OR length(p_decision_version) NOT BETWEEN 1 AND 128
     OR (p_request_id IS NOT NULL AND length(p_request_id) NOT BETWEEN 1 AND 256) THEN
    RAISE EXCEPTION 'Authorization audit field length is invalid';
  END IF;
  IF (p_resource_id IS NULL) <> (p_resource_type IS NULL) THEN
    RAISE EXCEPTION 'Resource ID and resource type must be supplied together';
  END IF;
  IF p_policy_id !~ '^mt3\.' THEN
    RAISE EXCEPTION 'Invalid policy identifier';
  END IF;

  v_expected_permission := CASE p_action
    WHEN 'soc:read' THEN 'soc:read'
    WHEN 'soc:write' THEN 'soc:write'
    WHEN 'soc:admin' THEN 'soc:admin'
    WHEN 'user:admin' THEN 'user:admin'
    WHEN 'incident:read' THEN 'incident:read'
    WHEN 'incident:write' THEN 'incident:write'
    WHEN 'governance:write' THEN 'governance:write'
    WHEN 'case:read' THEN 'case:read'
    WHEN 'case:create' THEN 'case:write'
    WHEN 'case:update' THEN 'case:write'
    WHEN 'case:close' THEN 'case:write'
    WHEN 'incident:create' THEN 'incident:write'
    WHEN 'investigation:read' THEN 'investigation:read'
    WHEN 'investigation:create' THEN 'investigation:write'
    WHEN 'investigation:update' THEN 'investigation:write'
    WHEN 'evidence:read' THEN 'evidence:read'
    WHEN 'evidence:add' THEN 'evidence:write'
    WHEN 'evidence:update' THEN 'evidence:write'
    WHEN 'evidence:delete' THEN 'evidence:write'
    WHEN 'task:read' THEN 'task:read'
    WHEN 'task:create' THEN 'task:write'
    WHEN 'task:update' THEN 'task:write'
    WHEN 'task:assign' THEN 'task:write'
    WHEN 'timeline:read' THEN 'timeline:read'
    WHEN 'timeline:append' THEN 'timeline:append'
    ELSE NULL
  END;
  IF p_allowed AND (v_expected_permission IS NULL OR p_permission <> v_expected_permission) THEN
    RAISE EXCEPTION 'Action and permission do not match';
  END IF;
  IF NOT p_allowed AND p_permission <> 'none' AND
     (v_expected_permission IS NULL OR p_permission <> v_expected_permission) THEN
    RAISE EXCEPTION 'Denied authorization audit must use none or the evaluated permission';
  END IF;

  SELECT i.provider_subject INTO v_identity_subject
    FROM explainsec_identities i
    JOIN explainsec_users u ON u.user_id = i.user_id
   WHERE i.user_id = p_user_id
     AND i.provider_type = 'firebase'
     AND i.status = 'ACTIVE'
     AND i.verified_at IS NOT NULL
     AND u.status = 'ACTIVE';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'User does not have an active verified Firebase identity';
  END IF;

  IF p_scope_type = 'TENANT' THEN
    v_tenant_id := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
    IF v_tenant_id IS NULL THEN
      RAISE EXCEPTION 'Tenant authorization audit requires transaction-local tenant context';
    END IF;
    IF p_organization_id IS NULL OR p_membership_id IS NULL THEN
      RAISE EXCEPTION 'Tenant authorization audit requires organization and membership';
    END IF;
    IF p_vendor_organization_id IS NOT NULL OR p_customer_organization_id IS NOT NULL
       OR p_portfolio_id IS NOT NULL OR p_relationship_id IS NOT NULL THEN
      RAISE EXCEPTION 'Tenant authorization audit has forbidden portfolio fields';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM explainsec_tenants t
       WHERE t.tenant_id = v_tenant_id
         AND t.organization_id = p_organization_id
    ) THEN
      RAISE EXCEPTION 'Tenant and organization do not match';
    END IF;
  ELSIF p_scope_type = 'ORGANIZATION' THEN
    IF COALESCE(current_setting('app.current_tenant_id', true), '') <> '' THEN
      RAISE EXCEPTION 'Organization authorization audit cannot use tenant context';
    END IF;
    IF p_organization_id IS NULL OR p_membership_id IS NULL THEN
      RAISE EXCEPTION 'Organization authorization audit requires organization and membership';
    END IF;
    IF p_vendor_organization_id IS NOT NULL OR p_customer_organization_id IS NOT NULL
       OR p_portfolio_id IS NOT NULL OR p_relationship_id IS NOT NULL THEN
      RAISE EXCEPTION 'Organization authorization audit has forbidden portfolio fields';
    END IF;
  ELSIF p_scope_type = 'PORTFOLIO' THEN
    IF COALESCE(current_setting('app.current_tenant_id', true), '') <> '' THEN
      RAISE EXCEPTION 'Portfolio authorization audit cannot use tenant context';
    END IF;
    IF p_vendor_organization_id IS NULL OR p_customer_organization_id IS NULL
       OR p_portfolio_id IS NULL OR p_relationship_id IS NULL THEN
      RAISE EXCEPTION 'Portfolio authorization audit scope is incomplete';
    END IF;
  ELSE
    IF COALESCE(current_setting('app.current_tenant_id', true), '') <> '' THEN
      RAISE EXCEPTION 'Platform authorization audit cannot use tenant context';
    END IF;
    IF p_membership_id IS NOT NULL OR p_organization_id IS NOT NULL
       OR p_vendor_organization_id IS NOT NULL OR p_customer_organization_id IS NOT NULL
       OR p_portfolio_id IS NOT NULL OR p_relationship_id IS NOT NULL THEN
      RAISE EXCEPTION 'Platform authorization audit has forbidden scope fields';
    END IF;
  END IF;

  IF p_membership_id IS NOT NULL THEN
    SELECT m.* INTO v_membership
      FROM explainsec_memberships m
     WHERE m.membership_id = p_membership_id
       AND m.user_id = p_user_id
       AND m.status = 'ACTIVE'
       AND m.effective_from <= now()
       AND (m.effective_until IS NULL OR m.effective_until > now());
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Membership is not active for the supplied user';
    END IF;
    IF p_organization_id IS NOT NULL AND v_membership.organization_id <> p_organization_id THEN
      RAISE EXCEPTION 'Membership and organization do not match';
    END IF;
    IF p_scope_type = 'TENANT' AND v_membership.tenant_id <> v_tenant_id THEN
      RAISE EXCEPTION 'Membership and tenant do not match';
    END IF;
  END IF;

  IF p_scope_type = 'PORTFOLIO' THEN
    IF NOT EXISTS (
      SELECT 1 FROM explainsec_portfolios p
       WHERE p.portfolio_id = p_portfolio_id
         AND p.vendor_organization_id = p_vendor_organization_id
         AND p.status = 'ACTIVE'
    ) OR NOT EXISTS (
      SELECT 1 FROM explainsec_vendor_relationships r
       WHERE r.relationship_id = p_relationship_id
         AND r.vendor_organization_id = p_vendor_organization_id
         AND r.customer_organization_id = p_customer_organization_id
         AND r.status = 'ACTIVE'
         AND r.effective_from <= now()
         AND (r.effective_until IS NULL OR r.effective_until > now())
    ) OR NOT EXISTS (
      SELECT 1 FROM explainsec_mssp_memberships mm
       WHERE mm.user_id = p_user_id
         AND mm.portfolio_id = p_portfolio_id
         AND mm.vendor_organization_id = p_vendor_organization_id
         AND mm.status = 'ACTIVE'
         AND mm.effective_from <= now()
         AND (mm.effective_until IS NULL OR mm.effective_until > now())
    ) OR NOT EXISTS (
      SELECT 1
        FROM explainsec_portfolio_organization_grants og
        JOIN explainsec_vendor_relationships gr
          ON gr.relationship_id = og.relationship_id
       WHERE og.portfolio_id = p_portfolio_id
         AND og.vendor_organization_id = p_vendor_organization_id
         AND og.customer_organization_id = p_customer_organization_id
         AND og.relationship_id = p_relationship_id
         AND og.status = 'ACTIVE'
         AND og.effective_from <= now()
         AND (og.effective_until IS NULL OR og.effective_until > now())
         AND gr.vendor_organization_id = p_vendor_organization_id
         AND gr.customer_organization_id = p_customer_organization_id
         AND gr.status = 'ACTIVE'
         AND gr.effective_from <= now()
         AND (gr.effective_until IS NULL OR gr.effective_until > now())
    ) THEN
      RAISE EXCEPTION 'Portfolio authorization scope is inconsistent';
    END IF;
  END IF;

  IF p_resource_id IS NOT NULL THEN
    IF p_resource_type = 'case' THEN
      SELECT tenant_id INTO v_resource_tenant FROM explainsec_cases WHERE case_id = p_resource_id;
    ELSIF p_resource_type = 'incident' THEN
      SELECT tenant_id INTO v_resource_tenant FROM explainsec_incidents WHERE incident_id = p_resource_id;
    ELSIF p_resource_type = 'investigation' THEN
      SELECT tenant_id INTO v_resource_tenant FROM explainsec_investigations WHERE investigation_id = p_resource_id;
    ELSIF p_resource_type = 'evidence' THEN
      SELECT tenant_id INTO v_resource_tenant FROM explainsec_evidence_metadata WHERE evidence_id = p_resource_id;
    ELSIF p_resource_type = 'task' THEN
      SELECT tenant_id INTO v_resource_tenant FROM explainsec_tasks WHERE task_id = p_resource_id;
    ELSIF p_resource_type = 'timeline' THEN
      SELECT tenant_id INTO v_resource_tenant FROM explainsec_timeline_entries WHERE timeline_entry_id = p_resource_id;
    ELSE
      RAISE EXCEPTION 'Invalid resource type';
    END IF;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Resource does not exist';
    END IF;
    IF p_scope_type = 'TENANT' AND v_resource_tenant <> v_tenant_id THEN
      RAISE EXCEPTION 'Resource and tenant do not match';
    ELSIF p_scope_type <> 'TENANT' THEN
      RAISE EXCEPTION 'Non-tenant audit events cannot reference tenant resources';
    END IF;
  END IF;

  INSERT INTO explainsec_authorization_audit (
    scope_type, user_id, organization_id, membership_id,
    vendor_organization_id, customer_organization_id, portfolio_id,
    relationship_id, tenant_id, action, permission, allowed, reason,
    policy_id, resource_id, resource_type, request_id, decision_version
  ) VALUES (
    p_scope_type, p_user_id, p_organization_id, p_membership_id,
    p_vendor_organization_id, p_customer_organization_id, p_portfolio_id,
    p_relationship_id, v_tenant_id, p_action, p_permission, p_allowed, p_reason,
    p_policy_id, p_resource_id, p_resource_type, p_request_id, p_decision_version
  )
  RETURNING audit_id INTO v_audit_id;
  RETURN v_audit_id;
END;
$$;

ALTER FUNCTION fn_record_authorization_decision(
  TEXT, UUID, UUID, UUID, UUID, UUID, UUID, UUID,
  TEXT, TEXT, BOOLEAN, TEXT, TEXT, UUID, TEXT, TEXT, TEXT
) OWNER TO explainsec_audit_writer;

REVOKE ALL ON FUNCTION fn_record_authorization_decision(
  TEXT, UUID, UUID, UUID, UUID, UUID, UUID, UUID,
  TEXT, TEXT, BOOLEAN, TEXT, TEXT, UUID, TEXT, TEXT, TEXT
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_record_authorization_decision(
  TEXT, UUID, UUID, UUID, UUID, UUID, UUID, UUID,
  TEXT, TEXT, BOOLEAN, TEXT, TEXT, UUID, TEXT, TEXT, TEXT
) TO explainsec_runtime;

REVOKE ALL ON explainsec_authorization_audit FROM explainsec_runtime;
GRANT USAGE ON SCHEMA public TO explainsec_runtime;
GRANT USAGE ON SCHEMA public TO explainsec_audit_writer;
GRANT INSERT ON explainsec_authorization_audit TO explainsec_audit_writer;
GRANT SELECT ON
  explainsec_users, explainsec_identities, explainsec_organizations,
  explainsec_tenants, explainsec_memberships, explainsec_vendor_relationships,
  explainsec_portfolios, explainsec_mssp_memberships,
  explainsec_portfolio_organization_grants, explainsec_portfolio_tenant_grants,
  explainsec_cases, explainsec_incidents, explainsec_investigations,
  explainsec_evidence_metadata, explainsec_tasks, explainsec_timeline_entries
TO explainsec_audit_writer;

ALTER FUNCTION explainsec_reject_authorization_audit_mutation()
  OWNER TO explainsec_audit_writer;
