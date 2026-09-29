# MT-4 tenant-aware SOC data layer

MT-4 adds PostgreSQL operational metadata for the resources represented by the
legacy SOC UI: cases (the legacy `issues` documents), incidents,
investigations, evidence metadata, tasks, and timeline entries. Every row is
owned by one tenant. Composite `(tenant_id, id)` foreign keys prevent a
resource in one tenant from referring to a parent in another tenant; database
checks also constrain lifecycle values and parent cardinality.

All six tables use forced row-level security. Runtime access is only through a
transaction created by `withTenantTransaction`, which sets the server-derived
MT-2 SecurityContext tenant. The MT-4 service invokes the MT-3 policy engine
and strips/rejects client tenant selectors. The runtime role remains
`NOBYPASSRLS`.

## Legacy discrepancies and deferred migration

Firestore `issues` documents and their `evidence` subcollections do not carry
an authoritative PostgreSQL tenant relationship. Existing rules also permit
broad authenticated reads/writes and evidence is immutable after creation.
Consequently MT-4 deliberately does **not** copy Firestore data, infer
ownership from `createdBy`, or migrate dashboards. A future migration must
obtain an authoritative tenant mapping from administrators, reconcile
duplicate/invalid lifecycle values, and separately import immutable evidence
metadata. Raw evidence blobs remain in their existing storage system.

Findings were not represented as a stable Firestore collection or domain
contract in MT-1–MT-3, so no findings table is invented. It can be added in a
later migration once its ownership and lifecycle semantics are specified.

## Commands

From `functions`, configure disposable PostgreSQL admin/runtime URLs and run
`npm run migrate`, then `npm run test:mt1`, `npm run test:mt2`,
`npm run test:mt3`, and `npm run test:mt4` in that order. Tests are skipped
when the URLs are absent.
