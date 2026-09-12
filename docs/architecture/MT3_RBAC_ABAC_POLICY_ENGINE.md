# MT-3 RBAC/ABAC policy engine

## Boundary

`functions/policyEngine.js` is the canonical server-side authorization
boundary. Authentication is still performed by Firebase and identity/scope
resolution remains the MT-2 PostgreSQL `SecurityContext`. The client never
supplies a role or permission decision.

The engine exposes `evaluatePolicy(input)` for a pure decision and
`authorize(input)` for the centralized decision/logging boundary. A decision
is structured (`ALLOW`/`DENY`, stable reason, subject/resource identifiers)
and defaults to deny for missing subjects/resources, unknown actions and
unknown roles. `throwOnDeny` is available for adapters that prefer an
exception; `AuthorizationError` preserves the decision.

## Model

The role-to-permission mapping is explicit and immutable. Canonical roles
include platform, organization, tenant, SOC L1/L2/manager, incident
responder, threat hunter, and MSSP analyst roles. Permission vocabulary
includes SOC, incident, governance, and user administration operations.
ABAC verifies:

* organization and tenant ownership from authoritative memberships;
* resource owner restrictions;
* active subject, resource lifecycle, and action/state constraints;
* MSSP boundary: `VENDOR_MEMBER` cannot access customer resources without an
  explicit `msspAccess: true` relationship;
* optional separation-of-duties and delegation callbacks;
* optional RLS handoff (`requireRlsHandoff` and `rlsTenantId`).

These checks are additive to, not a replacement for, MT-1 PostgreSQL RLS.
The SOC adapter invokes the canonical read boundary after MT-2 context
resolution while retaining legacy lifecycle/role checks during migration.
No SOC data or dashboard architecture is migrated in MT-3.

SOC roles are defined in the policy vocabulary even though the MT-1
foundational membership enum does not yet persist all operational role
assignments. Until those assignments are modeled authoritatively, missing
or unsupported persisted assignments remain denied; the policy engine does
not infer them from Firestore or frontend role values.

## Operations and tests

Run `npm run lint` from `functions`, `npm run test:mt3` for the disposable
PostgreSQL integration test, or `npm run test:integration` for MT-1 through
MT-3. Integration tests are skipped unless
`EXPLAINSEC_PG_RUNTIME_URL` and `EXPLAINSEC_PG_ADMIN_URL` are configured.
The MT-3 test covers positive/negative RBAC, tenant scope, lifecycle,
unknown input, MSSP spoofing, and the RLS handoff boundary.
