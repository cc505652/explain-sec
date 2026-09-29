DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_case_status') THEN
    CREATE TYPE explainsec_case_status AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED', 'ARCHIVED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_incident_status') THEN
    CREATE TYPE explainsec_incident_status AS ENUM ('OPEN', 'IN_PROGRESS', 'CONTAINMENT_PENDING', 'RESOLVED', 'CLOSED', 'ARCHIVED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_investigation_status') THEN
    CREATE TYPE explainsec_investigation_status AS ENUM ('OPEN', 'IN_PROGRESS', 'COMPLETED', 'CLOSED', 'ARCHIVED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'explainsec_task_status') THEN
    CREATE TYPE explainsec_task_status AS ENUM ('OPEN', 'ASSIGNED', 'IN_PROGRESS', 'BLOCKED', 'COMPLETED', 'CANCELLED');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS explainsec_cases (
  case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES explainsec_tenants(tenant_id),
  title TEXT NOT NULL, description TEXT, status explainsec_case_status NOT NULL DEFAULT 'OPEN',
  owner_user_id UUID REFERENCES explainsec_users(user_id), created_by UUID REFERENCES explainsec_users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, case_id), CHECK (length(trim(title)) > 0)
);
CREATE TABLE IF NOT EXISTS explainsec_incidents (
  incident_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES explainsec_tenants(tenant_id),
  case_id UUID, title TEXT NOT NULL, description TEXT, status explainsec_incident_status NOT NULL DEFAULT 'OPEN',
  severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  owner_user_id UUID REFERENCES explainsec_users(user_id), created_by UUID REFERENCES explainsec_users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, incident_id), CHECK (length(trim(title)) > 0),
  FOREIGN KEY (tenant_id, case_id) REFERENCES explainsec_cases(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS explainsec_investigations (
  investigation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES explainsec_tenants(tenant_id),
  case_id UUID NOT NULL, incident_id UUID, title TEXT NOT NULL,
  status explainsec_investigation_status NOT NULL DEFAULT 'OPEN',
  lead_user_id UUID REFERENCES explainsec_users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, investigation_id), CHECK (length(trim(title)) > 0),
  FOREIGN KEY (tenant_id, case_id) REFERENCES explainsec_cases(tenant_id, case_id),
  FOREIGN KEY (tenant_id, incident_id) REFERENCES explainsec_incidents(tenant_id, incident_id)
);
CREATE TABLE IF NOT EXISTS explainsec_evidence_metadata (
  evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES explainsec_tenants(tenant_id),
  incident_id UUID NOT NULL, storage_uri TEXT NOT NULL, media_type TEXT,
  sha256 TEXT, description TEXT, collected_at TIMESTAMPTZ,
  created_by UUID REFERENCES explainsec_users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, evidence_id), CHECK (length(trim(storage_uri)) > 0),
  FOREIGN KEY (tenant_id, incident_id) REFERENCES explainsec_incidents(tenant_id, incident_id)
);
CREATE TABLE IF NOT EXISTS explainsec_tasks (
  task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES explainsec_tenants(tenant_id),
  case_id UUID, incident_id UUID, investigation_id UUID, title TEXT NOT NULL,
  status explainsec_task_status NOT NULL DEFAULT 'OPEN', assignee_user_id UUID REFERENCES explainsec_users(user_id),
  due_at TIMESTAMPTZ, created_by UUID REFERENCES explainsec_users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, task_id), CHECK (length(trim(title)) > 0),
  CHECK (num_nonnulls(case_id, incident_id, investigation_id) = 1),
  FOREIGN KEY (tenant_id, case_id) REFERENCES explainsec_cases(tenant_id, case_id),
  FOREIGN KEY (tenant_id, incident_id) REFERENCES explainsec_incidents(tenant_id, incident_id),
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES explainsec_investigations(tenant_id, investigation_id)
);
CREATE TABLE IF NOT EXISTS explainsec_timeline_entries (
  timeline_entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES explainsec_tenants(tenant_id),
  case_id UUID, incident_id UUID, investigation_id UUID, task_id UUID,
  event_type TEXT NOT NULL, summary TEXT NOT NULL, event_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_user_id UUID REFERENCES explainsec_users(user_id), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, timeline_entry_id), CHECK (num_nonnulls(case_id, incident_id, investigation_id, task_id) = 1),
  CHECK (length(trim(event_type)) > 0 AND length(trim(summary)) > 0),
  FOREIGN KEY (tenant_id, case_id) REFERENCES explainsec_cases(tenant_id, case_id),
  FOREIGN KEY (tenant_id, incident_id) REFERENCES explainsec_incidents(tenant_id, incident_id),
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES explainsec_investigations(tenant_id, investigation_id),
  FOREIGN KEY (tenant_id, task_id) REFERENCES explainsec_tasks(tenant_id, task_id)
);

CREATE INDEX IF NOT EXISTS explainsec_cases_tenant_idx ON explainsec_cases(tenant_id);
CREATE INDEX IF NOT EXISTS explainsec_incidents_tenant_idx ON explainsec_incidents(tenant_id);
CREATE INDEX IF NOT EXISTS explainsec_investigations_tenant_idx ON explainsec_investigations(tenant_id);
CREATE INDEX IF NOT EXISTS explainsec_evidence_tenant_idx ON explainsec_evidence_metadata(tenant_id);
CREATE INDEX IF NOT EXISTS explainsec_tasks_tenant_idx ON explainsec_tasks(tenant_id);
CREATE INDEX IF NOT EXISTS explainsec_timeline_tenant_idx ON explainsec_timeline_entries(tenant_id, event_at);

DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['explainsec_cases','explainsec_incidents','explainsec_investigations','explainsec_evidence_metadata','explainsec_tasks','explainsec_timeline_entries'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_select', table_name);
    EXECUTE format('CREATE POLICY %I ON %I FOR SELECT USING (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name || '_select', table_name);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_insert', table_name);
    EXECUTE format('CREATE POLICY %I ON %I FOR INSERT WITH CHECK (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name || '_insert', table_name);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_update', table_name);
    EXECUTE format('CREATE POLICY %I ON %I FOR UPDATE USING (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name || '_update', table_name);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_delete', table_name);
    EXECUTE format('CREATE POLICY %I ON %I FOR DELETE USING (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid)', table_name || '_delete', table_name);
  END LOOP;
END $$;
