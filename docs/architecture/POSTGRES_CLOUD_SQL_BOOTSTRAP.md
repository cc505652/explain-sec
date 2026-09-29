# PostgreSQL and Cloud SQL bootstrap authority

The application migration identity is deliberately a non-superuser, non-bypass
role. Cloud SQL is managed PostgreSQL and must not be treated as an unrestricted
local `postgres` installation.

## Separate privilege domains

Schema ACLs and object ACLs are separate privilege domains:

- `USAGE` and `CREATE` on `public` allow object access and creation.
- Changing the schema ACL for another role requires schema ownership or grant
  authority.
- The migration identity owns or controls objects created by migrations and may
  grant the required object-level privileges on those objects.
- Runtime object privileges and the audit function's `EXECUTE` privilege remain
  application migration concerns.

The application migration does not attempt to alter the externally owned
`public` schema ACL. `functions/db/runtimeRole.js` likewise grants only
object-level runtime privileges and function `EXECUTE`; it never grants schema
privileges.

## One-time Cloud SQL bootstrap

Before first runtime use, a Cloud SQL administrator or other schema grant-capable
bootstrap identity must establish the minimum schema access:

```sql
GRANT USAGE ON SCHEMA public TO explainsec_runtime;
GRANT USAGE ON SCHEMA public TO explainsec_audit_writer;
```

These statements are deployment/bootstrap actions, not migration statements.
They must be executed through the approved Cloud SQL administrative process and
must not be added to application `.env` files, migration SQL, or runtime code.
No credentials, connection URLs, CA files, or service-account material belong
in this repository.

The bootstrap identity must also ensure that the migration executor has the
required `CREATE` and `USAGE` access on `public`, and that migration-created
objects are owned or controlled by `explainsec_migrator` sufficiently for the
object-level grants in migrations 001 through 004. The audit writer remains
`NOLOGIN`, non-superuser, non-bypass, and is not made a database owner.

## Role boundaries

- `explainsec_migrator` remains separate from runtime and does not require
  `SUPERUSER` or `BYPASSRLS`.
- `explainsec_runtime` remains `LOGIN`, `NOSUPERUSER`, `NOCREATEDB`,
  `NOCREATEROLE`, and `NOBYPASSRLS`; it receives no schema DDL authority and no
  direct audit-table DML.
- `explainsec_audit_writer` remains `NOLOGIN`, `NOSUPERUSER`, `NOCREATEDB`,
  `NOCREATEROLE`, and `NOBYPASSRLS`.
- `fn_record_authorization_decision` remains `SECURITY DEFINER`, uses a fixed
  `search_path`, is owned by `explainsec_audit_writer`, and is executable by
  runtime only.
- `explainsec_authorization_audit` remains append-only with enabled and forced
  RLS.

Migration 004 therefore assumes the bootstrap schema grants already exist,
continues to grant object privileges required by the controlled audit function,
and remains idempotent. It does not grant schema ACLs or make runtime or audit
writer roles database owners.
