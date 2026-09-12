# MT-1 PostgreSQL authority and multi-tenancy foundation

MT-1 adds the PostgreSQL foundation without replacing Firebase Authentication,
migrating Firestore data, or changing existing SOC behavior.

## Roles

`EXPLAINSEC_PG_ADMIN_URL` is used only by `npm run migrate` for schema
migrations and controlled fixture setup. Normal request handlers must not load
this connection.

`EXPLAINSEC_PG_RUNTIME_URL` is the normal application connection. The role
identified by `EXPLAINSEC_PG_RUNTIME_ROLE` must exist and have
`rolbypassrls = false`. The migration command verifies LOGIN, NOSUPERUSER, NOCREATEDB,
NOCREATEROLE, and NOBYPASSRLS before succeeding.

The migration creates the `explainsec_runtime` role as a non-login role with
`NOBYPASSRLS`. Deployment must grant login and configure its connection secret
outside the repository. Do not commit passwords:

```sql
ALTER ROLE explainsec_runtime LOGIN;
```

The deployment may grant login through its secret-management process. The
runtime role must receive only the grants needed by the application.

## Tenant context

Tenant-owned operations must run through `withTenantTransaction(pool, tenantId,
operation)`. It validates a UUID, starts a transaction, executes:

```sql
SELECT set_config('app.current_tenant_id', '<validated-id>', true);
```

The setting is transaction-local and therefore cannot leak through a pooled
connection. Missing context produces no visible rows in the MT-1 RLS probe;
invalid context is rejected before a connection is used.

## MT-1 tables

The migration creates:

- `explainsec_users`
- `explainsec_identities`
- `explainsec_organizations`
- `explainsec_tenants`
- `explainsec_memberships`
- `explainsec_mt1_rls_probe`

The probe is only a reusable RLS foundation test table. It is not an EXPLAINSEC
SOC resource and must not be treated as one.

Membership supports platform, organization, tenant, and vendor scope. An
organization membership does not grant tenant access. Owner, organization
admin, and tenant admin roles are scoped by membership constraints.

The database trigger protects the normal minimum-one-owner invariant. Full
ownership transfer, quorum approval, delegated tenant-admin appointment,
portfolio authorization, and break-glass workflows remain deferred.

## Deferred work

MT-1 does not implement:

- complete RBAC/ABAC or policy evaluation;
- MSSP portfolios and grants;
- cross-tenant correlation;
- Case/Incident/Investigation migration;
- Firestore migration or cutover;
- break-glass;
- the complete Firebase UID-to-membership authorization flow;
- production tenant lifecycle/deletion workflows.

Run the real PostgreSQL integration tests with both role URLs configured:

```powershell
npm run migrate
npm run test:mt1
```
