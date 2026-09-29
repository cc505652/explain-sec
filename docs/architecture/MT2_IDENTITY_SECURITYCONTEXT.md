# MT-2 identity and SecurityContext

## Purpose

MT-2 makes Firebase authentication and PostgreSQL authorization separate
concerns. A verified Firebase UID is only an identity hint; authorization is
resolved by `functions/securityContext.js` from the MT-1 PostgreSQL tables.

## Resolution contract

`resolveSecurityContext(verifiedFirebaseUid, { organizationId, tenantId })`
requires an explicit organization selector (and requires it when a tenant is
selected). It requires a Firebase identity that is active and verified, an
active user, active non-expired memberships, and active organization/tenant
records. Tenant memberships never grant organization-wide access, and a tenant
selector cannot cross organizations. Missing, inactive, expired, mismatched,
or conflicting records fail closed.

The returned context contains the database user, selected scope, database
roles, memberships, and a conservative server-derived permission set. It and
all nested collections are immutable. Client-supplied roles and permissions
are ignored.

Authentication, identity, membership, authorization, and isolation remain
distinct:

1. Firebase Admin verifies the bearer ID token and supplies the Firebase UID.
2. `explainsec_identities` maps that UID to an EXPLAINSEC user.
3. `explainsec_users` supplies lifecycle status.
4. `explainsec_memberships` supplies scoped organization or tenant roles.
5. The resolver derives capabilities from the persisted scoped role.
6. PostgreSQL RLS remains the final tenant data-isolation boundary.

Organization selection is not proof of membership. Tenant selection is not
proof of tenant access. A tenant membership never becomes an organization-wide
membership, and every tenant switch repeats the complete resolution query.

The context exposes immutable identity, request, session, authentication
strength, organization and tenant status, active membership, effective roles,
effective permissions, and the resolved membership set. It does not expose a
client mutation API. Organization and tenant IDs are request selectors only;
the returned values are taken from the matching PostgreSQL records.

## Authorization boundary

The MT-2 capability set is deliberately conservative. A role is not a
blanket grant: future RBAC capability checks must still apply ABAC conditions,
resource ownership, lifecycle state, and tenant policy. Unknown roles produce
no derived permissions. Platform-admin status does not bypass RLS.

| Role | Organization | Tenant | Initial capability boundary |
| --- | --- | --- | --- |
| Organization owner/admin | scoped | not implied | policy-controlled read |
| Organization member | scoped | not implied | scoped read |
| Tenant admin | related organization | explicit tenant | tenant read/write |
| Vendor member | vendor relationship | explicit relationship | scoped read |
| Platform admin | platform | not implied | platform read; no RLS bypass |

The current MT-1 schema contains the foundational organization, tenant, and
membership roles. SOC-specific roles, portfolios, delegation, break-glass,
and full MSSP policy evaluation remain deferred.

## HTTP boundary

`functions/socActions.js` verifies the Firebase ID token with Firebase Admin
and immediately resolves the PostgreSQL context using selectors in the
request body. Existing action authorization reads `auth.context`, never the
Firestore `users/{uid}.role` profile. Selectors are authorization inputs, not
proof of access; PostgreSQL membership remains authoritative.

Authentication failures and authorization failures are separate: an invalid
Firebase token is rejected as authentication failure, while a valid token
with no matching PostgreSQL identity or membership is rejected as
authorization failure. The protected HTTP functions require an explicit
organization selector (and tenant selector where tenant scope is needed).

## RLS compatibility

MT-2 does not alter the MT-1 migration, policies, or runtime role. Tenant
transactions must continue to use the existing transaction-local
`app.current_tenant_id` setting.

## Legacy paths and scope

This change does **not** claim to migrate all SOC data access. Existing client
Firestore reads and any legacy direct-write paths outside the protected
`socActions` functions remain in place and must be removed or separately
secured in a later migration phase. The client dispatcher in
`src/utils/socFunctions.js`, direct workflow writes in dashboard components,
and permissive legacy Firestore rules are not claimed as fixed by MT-2.
No broad SOC data migration is performed here.

## Tests

`functions/test/mt2.integration.test.js` is a PostgreSQL integration suite
that exercises unknown identity denial, organization and tenant scope
isolation, organization-only tenant denial, cross-organization selectors,
conflicting selectors, expiry, immutable contexts, and server-derived roles.
It is skipped unless the configured runtime and admin PostgreSQL URLs are
present. `test:integration` runs MT-1 and MT-2 sequentially because both
suites use a disposable shared database during local validation.

## Deferred functionality

MT-2 does not migrate Firestore data, replace the frontend architecture,
implement complete SOC role assignment, portfolio grants, delegation,
break-glass, Case/Incident/Investigation persistence, or production cutover.
Those changes require explicit follow-on authorization and data-migration
design and are outside this phase.
