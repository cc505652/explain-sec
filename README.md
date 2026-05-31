# 🛡️ ExplainSec — Security Operations Platform

> A production-grade Security Operations Platform modeling real-world SOC workflows: incident response, threat hunting, governance, post-incident review, and root cause analysis — with server-enforced authorization, immutable audit logging, and lifecycle-driven orchestration.

![version](https://img.shields.io/badge/version-v1.0.0-blue)
![status](https://img.shields.io/badge/phase-1%20final%20stable-brightgreen)
![tests](https://img.shields.io/badge/tests-465%2F465-brightgreen)
![security](https://img.shields.io/badge/security-server%20enforced-red)
![architecture](https://img.shields.io/badge/architecture-SOC%20platform-blueviolet)

---

## 🚀 Project Overview

ExplainSec is a full-stack Security Operations Center platform that models the complete lifecycle of a security incident — from initial triage through investigation, escalation, containment, governance, threat hunting, post-incident review, and root cause analysis.

The platform is built around one core principle:

> Every security-relevant write goes through a Cloud Function. The client is untrusted.

Most security projects stop at detection. ExplainSec starts where detection ends:

- Who is authorized to act, and at what point in the lifecycle?
- Which state transitions are valid, and who can trigger them?
- How is every decision recorded, audited, and made forensically reliable?
- How does a SOC team formally review, learn from, and close an incident?

This project models operational reality — not just alerts, but decisions, approvals, governance holds, and accountability chains.

---

## 🎯 Why This Project Exists

Real SOC operations involve layered workflows that most security tooling either ignores or simplifies beyond recognition. ExplainSec was built to model the full operational picture:

```
Detection
    ↓
Triage & Classification          (L1 Analyst)
    ↓
Investigation & Evidence         (L2 Analyst)
    ↓
Escalation Approval              (SOC Manager gate)
    ↓
Containment & Response           (IR Team)
    ↓
Containment Approval             (SOC Manager gate)
    ↓
Resolution
    ↓
Post-Incident Review / RCA / Risk Acceptance   (decoupled branches)
```

Every stage has defined role boundaries, valid transitions, mandatory justifications, and immutable audit records. That is what this platform simulates.

---

## 👥 Roles

| Role | Responsibilities |
|------|-----------------|
| **Student** | Submit incident reports, track progress |
| **SOC L1 Analyst** | Triage, classify, claim, escalate incidents |
| **SOC L2 Analyst** | Investigate, gather evidence, escalate to IR |
| **IR Analyst** | Execute containment, submit for Manager approval |
| **Threat Hunter** | Conduct proactive threat hunt investigations |
| **SOC Manager** | Approve escalations/containment, governance controls, PIR/RCA/risk decisions |
| **Administrator** | Manage users, assign roles, configure platform access |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        REACT FRONTEND                           │
│                                                                 │
│  StudentDashboard   L1Dashboard    L2Dashboard                  │
│  IRDashboard        ThreatHunterDashboard                       │
│  SOCManagerDashboard   AdminDashboard                           │
│  SOCManager_CommandConsole                                      │
│                                                                 │
│  ┌────────────────────────────────────┐                         │
│  │       Client-Side Wrappers         │                         │
│  │   src/utils/socFunctions.js        │                         │
│  │   callGovernanceAction()           │                         │
│  │   callApproveEscalation()          │                         │
│  │   callApproveContainment()  ...    │                         │
│  └────────────────┬───────────────────┘                         │
└───────────────────┼─────────────────────────────────────────────┘
                    │  Firebase Callable Functions (HTTPS)
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FIREBASE CLOUD FUNCTIONS                     │
│                   functions/socActions.js                       │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  governanceActions (unified dispatcher)                  │   │
│  │  ├─ OVERRIDE_DECISION      ├─ SLA_OVERRIDE               │   │
│  │  ├─ TRANSFER_OWNERSHIP     ├─ CONVERT_TO_THREAT_HUNT     │   │
│  │  ├─ REOPEN_INCIDENT        ├─ REJECT_CONTAINMENT         │   │
│  │  ├─ ACCEPT_RISK            ├─ TAG_RCA    ├─ TAG_PIR      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  escalateIncident    approveEscalation   denyEscalation         │
│  performContainment  approveContainment  lockIncident           │
│  updateRole          updateIncidentStatus                       │
│                                                                 │
│  Security layers applied to EVERY function:                     │
│  1. Firebase Auth token verification                            │
│  2. Role fetched from Firestore via Admin SDK                   │
│  3. Governance lock check (assertNotLocked)                     │
│  4. State machine validation (TRANSITIONS map)                  │
│  5. Mandatory reason enforcement                                │
│  6. Idempotency guard                                           │
│  7. writeAuditLog (immutable — client cannot forge)             │
└─────────────────────────────────────────────────────────────────┘
                    │  Admin SDK (bypasses Firestore rules)
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                        FIRESTORE                                │
│                                                                 │
│  /issues/{id}            Incident documents                     │
│  /incident_timeline/{id} Immutable chronological event log      │
│  /users/{uid}            User profiles + roles (RBAC source)    │
│  /audit_logs/{id}        Immutable (client create/update: false)│
│  /notifications/{id}     Role-scoped real-time alerts           │
│  /roles/{id}             Role definitions                       │
│  /config/{id}            Platform configuration                 │
└─────────────────────────────────────────────────────────────────┘
```

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| All critical writes via Cloud Functions | Eliminates client-side bypass. Admin SDK ignores rules, giving functions full authority. |
| Role stored in Firestore, read by Admin SDK | Client cannot spoof role via JWT claims or local state. |
| Single `governanceActions` dispatcher | Avoids function sprawl; one auth + lock + audit pipeline shared by all governance ops. |
| Firestore rules as defence layer, not primary | Functions are primary enforcement; rules add defence-in-depth for direct DB access attempts. |
| State machine on server, mirrored on client | Client guard is UX only; server rejects all invalid transitions regardless. |
| Write-split pattern for Firestore updates | Splits scalar writes from `arrayUnion` writes to eliminate contention under concurrent analyst load. |
| `actorRole` always explicit in audit events | Prevents implicit role inference bugs — every audit record carries the verified role at time of action. |

---

## ⚙️ Platform Engines

### Permission Engine (`src/security/permissions.js`)

Centralized, deny-by-default ABAC authorization layer.

- Explicit permission constants — no magic strings
- Set-based role-to-permission mapping — no numeric threshold inheritance
- Safe defaults: unknown role or permission → `false`
- `canUser(user, permission)` and `hasPermission(role, permission)` as canonical check functions
- `getPermissionMatrix()` for admin introspection

Designed to replace scattered inline role checks across the platform in Phase 2.

---

### Governance Engine (`functions/socActions.js` — `governanceActions`)

Single authenticated dispatcher for all SOC Manager operations.

Every action passes through the same enforcement pipeline:

```javascript
// 1. Auth check
if (!request.auth) throw unauthenticated

// 2. Role check (Admin SDK — cannot be spoofed)
const { role } = await getCallerRole(uid)
if (role !== "soc_manager" && role !== "admin") throw permission-denied

// 3. Incident lock check
await assertNotLocked(incidentRef, role)

// 4. Mandatory reason (≥3 chars, server-side)
if (!payload.reason || reason.trim().length < 3) throw invalid-argument

// 5. State machine validation
const check = validateTransition(currentStatus, newStatus)
if (!check.valid) throw failed-precondition

// 6. Idempotency
if (duplicate action detected) throw failed-precondition / already-exists

// 7. Commit + immutable audit log
await incidentRef.update(update)
await writeAuditLog(...)
```

---

### Timeline Engine (`src/security/timelineEngine.js`)

Chronological event reconstruction for every incident.

Captures:

- Status transitions
- Escalation events (requested, approved, denied)
- Containment events (requested, approved, rejected, executed)
- Governance events (lock, unlock, override, risk acceptance)
- Threat Hunt events (conversion, assignment, findings)
- PIR and RCA lifecycle events
- Assignment and reassignment history

All events are written to a flat, queryable `incident_timeline` collection. Client writes to this collection are unconditionally blocked.

---

### Audit Engine (`src/security/auditEngine.js`)

Immutable security event log.

- Explicit action constants — no raw strings
- Standardized event schema with validation
- Detached Firestore writes (fire-and-forget, non-blocking)
- In-memory deduplication ring buffer (16-entry, 3-second window)
- `actorRole` always explicit — never inferred
- Domain wrappers for escalation, containment, governance, and investigation events

---

### SLA Engine (`src/utils/slaEngine.js`)

Centralized SLA computation — single source of truth.

Provides:

- SLA deadline calculation per incident status
- Breach detection
- At-risk detection
- Time remaining / elapsed formatting
- SLA override recording with `slaOverrideBy`, `slaOverrideAt` fields

---

### Incident State Guard (`src/utils/incidentStateGuard.js`)

Client-side UX mirror of the server state machine.

Prevents invalid transition UI from rendering — not a security control. The server independently validates all transitions.

---

## 🔐 Security Model

### Threat Model — What Was Hardened

| Attack Vector | Mitigation |
|--------------|------------|
| Client forges role in request | Role always fetched from Firestore via Admin SDK in every function. JWT role claims ignored. |
| Direct `updateDoc` to change `status` | `status` blocked in Firestore rules for all non-Admin roles. Only Cloud Functions write it. |
| Client writes fake `statusHistory` entry | `statusHistory` and `investigationHistory` explicitly removed from all client-writable field allowlists. |
| Escalation bypass (write `escalationApproved: true`) | `escalationApproved` blocked in rules create/update for all non-Admin roles. |
| Role self-escalation via `/users` | Role, team, analystLevel blocked in user profile self-update rule. |
| Duplicate governance action spam | Idempotency guard per action: `already-exists` or `failed-precondition` thrown before any write. |
| Locked incident modification | `assertNotLocked()` runs in every function; Firestore `isNotLocked()` for direct-write paths. |
| Governance field override via OVERRIDE_DECISION | `OVERRIDE_DECISION` allowlist restricted to `["triageStatus", "urgency"]` only. |
| Audit log injection from client | `/audit_logs` collection: `create: false`, `update: false`, `delete: false` — unconditional. |
| Timeline injection from client | `/incident_timeline` collection: client write unconditionally blocked. |

### Firestore Rules — Tier System

```
TIER 1 — Admin:             Full write access (Admin role only)
TIER 2 — SOC Manager:       Direct write limited to managerNotes, isDeleted only
                             All sensitive operations → Cloud Functions
TIER 3a — IR Team:          status + containment fields on assigned incidents, not locked
TIER 3b — Assigned Analyst: urgency, triageStatus, analystNotes on own assigned incidents
TIER 3c — Any Analyst:      Can self-claim open/unassigned incident (status: assigned only)
```

### Defence-in-Depth (Three Layers)

```
Layer 1: UI guards        (UX only — not trusted)
Layer 2: Firestore rules  (field-level ACL — defence in depth)
Layer 3: Cloud Functions  (primary enforcement — authoritative)
```

An attacker must bypass all three simultaneously. Layer 3 always runs Admin SDK, which is immune to Firestore security rules.

---

## 🔄 Incident Lifecycle

```
[Student Submits]
      │
      ▼
   open ──────────────────────────────────────────┐
      │                                           │
      ▼                                         threat_hunt
   assigned                                       │
      │                                           ├──► open
      ▼                                           ├──► in_progress
  in_progress ─────────────────────────► resolved ├──► resolved
      │                                   │       └──► rca_pending
      ▼                                   │
  confirmed_threat                        ├──► reopened ──► open/assigned
      │                                   │
      ▼                                   ├──► rca_pending ──► rca_completed ──► resolved
  escalation_pending                      │
      │ (L2 requests)                     ├──► pir_pending ──► pir_completed ──► resolved
      ▼
  escalation_approved ─────────────────── └──► risk_accepted ──► resolved
      │ (Manager approves)
      ▼
  ir_in_progress
      │
      ▼
  containment_pending ◄──── REJECT_CONTAINMENT (Manager rejects → ir_in_progress)
      │
      ▼
  contained
      │ (Manager approveContainment)
      ▼
   resolved
      │
   false_positive ──► open / resolved / risk_accepted
```

### Escalation Gate (Critical Path)

```
L2 Analyst           SOC Manager          IR Team
    │                    │                    │
    │ escalateIncident()  │                    │
    ├───────────────────► │                    │
    │                    │ approveEscalation() │
    │                    ├───────────────────► │
    │                    │  (or denyEscalation)│
    │                    │                    │ performContainment()
    │                    │ ◄──────────────────┤
    │                    │ approveContainment()│
    │                    ├───────────────────► │
    │                 resolved                 │
```

### Post-Resolution Branches (Decoupled)

```
resolved ──► rca_pending ──► rca_completed ──► resolved   (independent)
resolved ──► pir_pending ──► pir_completed ──► resolved   (independent)
resolved ──► risk_accepted ──► resolved                   (independent)
```

PIR, RCA, and Risk Acceptance are fully decoupled — no forced sequencing. An incident can be PIR-tagged without RCA, preventing both workflow bottlenecks and state machine deadlocks.

---

## ⚙️ Governance System

All SOC Manager advanced operations are dispatched through a single authenticated Cloud Function: `governanceActions`.

### Action Types

| Action | Trigger | Precondition | Effect |
|--------|---------|-------------|--------|
| `OVERRIDE_DECISION` | Manager overrides triage/urgency | Not resolved | Updates `triageStatus` or `urgency`, logs override |
| `SLA_OVERRIDE` | Force urgency escalation | Any active status | Sets urgency + `slaOverride: true`, `slaOverrideBy`, `slaOverrideAt` |
| `TRANSFER_OWNERSHIP` | Reassign to different team | Not same team (idempotency guard) | Updates `assignedTo`, optionally sets escalation if IR |
| `CONVERT_TO_THREAT_HUNT` | Divert to hunt case | Not resolved/pir/rca | Status → `threat_hunt`, assigns to Threat Hunter |
| `REOPEN_INCIDENT` | Reopen closed incident | Status: `resolved` only | Status → `reopened` via state machine |
| `REJECT_CONTAINMENT` | Reject IR's containment | Status: `contained`/`containment_pending` | Status → `ir_in_progress`, flags rejection |
| `ACCEPT_RISK` | Formally accept residual risk | Decision-point status | Status → `risk_accepted`, logs acceptance reason |
| `TAG_RCA` | Tag for Root Cause Analysis | Post-resolution status | Status → `rca_pending`, sets `RCARequired: true` |
| `TAG_PIR` | Tag for Post Incident Review | `resolved`/`rca_completed` | Status → `pir_pending`, sets `PIRRequired: true` |

---

## 📊 Dashboards

### 🟡 L1 Analyst Dashboard
- View and self-claim open incidents from the live queue
- Update triage status, classification, and analyst notes
- Submit escalation requests
- All writes scoped to own assigned incidents only

### 🟠 L2 Analyst Dashboard
- Escalated incident investigation queue
- Request escalation to IR Team via `escalateIncident` Cloud Function
- Investigation notes and evidence tracking
- Confirm threat classification before escalation

### 🔴 IR Analyst Dashboard
- Containment-focused view of IR-assigned incidents
- Submit containment actions via `performContainment` Cloud Function
- `readyForManagerReview` flag triggers Manager approval queue
- Cannot approve own containment — Manager gate required

### 🟤 Threat Hunter Dashboard
- Threat Hunt investigation queue
- ATT&CK-mapped investigation workspace
- Hunt findings and submission workflow
- Approval gate before closure

### 🟣 SOC Manager Dashboard
- Full governance control panel across all active incidents
- Approve/deny escalations and containment requests
- Access to all 9 `governanceActions` operation types
- Lock/unlock incidents for governance holds
- Real-time escalation and containment approval queues
- PIR, RCA, and Risk Acceptance workflow management

### 🖥️ Command Console
- Dedicated SOC Manager cross-incident operational view
- Aggregated SLA breach indicators and hotspot tracking
- Incident throughput and queue health metrics

### 🔷 Admin Dashboard
- User management: create, assign, update roles
- RBAC configuration via `updateRole` Cloud Function
- Full incident visibility across all queues

---

## 🧪 Validation & Security Testing

### Attack Simulation Matrix

| Attack | Vector | Expected | Status |
|--------|--------|----------|--------|
| Role escalation | Direct `updateDoc` to `/users/{uid}` with `role: soc_manager` | `permission-denied` (rules block self-write of `role`) | ✅ BLOCKED |
| Escalation bypass | `updateDoc(issueId, { escalationApproved: true })` | `permission-denied` (field not in any client allowlist) | ✅ BLOCKED |
| Status manipulation | `updateDoc(issueId, { status: "resolved" })` from analyst | `permission-denied` (`status` not in TIER 3b allowlist) | ✅ BLOCKED |
| Locked incident modification | Any write on `locked: true` incident from non-manager | `permission-denied` (`isNotLocked()` guard + function layer) | ✅ BLOCKED |
| Audit log injection | `addDoc("audit_logs", { ... })` from any client | `permission-denied` (`create: false` unconditional rule) | ✅ BLOCKED |
| Unauthorized role update | `callUpdateRole()` from analyst | `permission-denied` (function: admin role required) | ✅ BLOCKED |
| Duplicate threat hunt | `CONVERT_TO_THREAT_HUNT` on already-hunted incident | `already-exists` (idempotency guard) | ✅ BLOCKED |
| Override escalation field | `OVERRIDE_DECISION` with `targetField: escalationRequested` | `invalid-argument` (not in ALLOWED_FIELDS) | ✅ BLOCKED |
| Same-team transfer spam | `TRANSFER_OWNERSHIP` to current team | `failed-precondition` (idempotency guard) | ✅ BLOCKED |
| Client statusHistory injection | `updateDoc(issueId, { statusHistory: [...] })` | `permission-denied` (removed from all client allowlists) | ✅ BLOCKED |

### Functional Regression Matrix

| Workflow | Status |
|----------|--------|
| L1 → triage → escalation request | ✅ WORKING |
| L2 → investigation → IR escalation | ✅ WORKING |
| Manager → approve escalation → IR | ✅ WORKING |
| IR → containment → Manager review | ✅ WORKING |
| Manager → approve containment → resolved | ✅ WORKING |
| Manager → reject containment → ir_in_progress | ✅ WORKING |
| Manager → REOPEN_INCIDENT | ✅ WORKING |
| Manager → CONVERT_TO_THREAT_HUNT | ✅ WORKING |
| Threat Hunt → open (exit path) | ✅ WORKING |
| Manager → TAG_PIR → pir workflow | ✅ WORKING |
| Manager → TAG_RCA → rca workflow | ✅ WORKING |
| PIR independent of RCA | ✅ WORKING |
| RCA independent of PIR | ✅ WORKING |
| Risk Acceptance independent of PIR/RCA | ✅ WORKING |
| Manager → ACCEPT_RISK | ✅ WORKING |
| Governance lock → blocks all analyst writes | ✅ WORKING |

---

## 📈 Why ExplainSec Stands Out

### 1. Zero-Trust Client Architecture
Every security decision is made server-side. The client can read authorized data and submit requests — it cannot directly mutate anything that influences security posture, workflow state, or audit records.

### 2. Single Governance Dispatcher
All 9 manager-level operations share one authenticated, audited, lock-checked pipeline via `governanceActions`. This mirrors SOAR (Security Orchestration, Automation and Response) design principles rather than proliferating individual Cloud Functions.

### 3. Decoupled Post-Incident Branches
PIR, RCA, and Risk Acceptance are independent state machine branches from `resolved`. They do not force each other — preventing both workflow bottlenecks and state machine deadlocks.

### 4. Immutable Forensic Trail
`statusHistory` and `auditLog` entries are written exclusively by Cloud Functions using `FieldValue.arrayUnion` and direct Admin SDK writes. No client path exists to forge, modify, or delete entries. The audit trail is forensically reliable.

### 5. Governance Lock
SOC Manager can place a governance hold on any incident, freezing all analyst and IR writes at both the rules layer (`isNotLocked()`) and the function layer (`assertNotLocked()`). Prevents in-flight modifications during sensitive review phases.

### 6. Write-Split Contention Handling
Combining `serverTimestamp()` with `arrayUnion()` in a single Firestore update causes read-modify-write contention under concurrent analyst load. All writes are split — scalars first, array operations second — eliminating this class of bug.

### 7. Deterministic System Behaviour
The system is validated to behave deterministically under controlled execution (`--workers=1`), reducing race conditions and state inconsistencies across concurrent workflows.

---

## 💼 Real-World Relevance

| ExplainSec Capability | Real-World Equivalent |
|----------------------|----------------------|
| Approval-based containment gate | Enterprise IR approval workflows |
| Single `governanceActions` dispatcher | SOAR platform architecture |
| Immutable audit logging | ISO 27001 / SOC 2 audit trail requirements |
| Role-isolated dashboards | Tiered SOC analyst structure |
| PIR workflow | Post-incident lessons-learned process |
| RCA workflow | Root cause tracking for systemic fixes |
| Governance lock | Change freeze / CAB hold during incident review |
| Idempotency guards | Duplicate action prevention in real ITSM platforms |

---

## 📌 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, React Router v6, Vite |
| **State / Real-time** | Firestore `onSnapshot` (no Redux needed) |
| **Backend Functions** | Firebase Cloud Functions v2 (Node.js 24) |
| **Database** | Cloud Firestore (NoSQL) |
| **Auth** | Firebase Authentication |
| **Security** | Firebase Admin SDK, Firestore Security Rules |
| **Testing** | Playwright (end-to-end) |
| **Deployment** | Firebase Hosting + Cloud Functions (`asia-south1`) |
| **Styling** | Vanilla CSS, glassmorphism dark-mode design system |
| **AI Integration** | Google Gemini 1.5 Flash — planned expansion |

---

## 🗂 Project Structure

```
/
├── src/
│   ├── AnalystDashboard.jsx             # L1 / L2 combined
│   ├── SOCManagerDashboard.jsx          # Governance control panel
│   ├── SOCManager_CommandConsole.jsx    # Ops overview
│   ├── AdminDashboard.jsx
│   ├── firebase.js
│   ├── security/
│   │   ├── permissions.js              # Centralized ABAC permission engine
│   │   ├── auditEngine.js              # Immutable security event logger
│   │   ├── timelineEngine.js           # Incident timeline reconstruction
│   │   ├── policies.js                 # Governance policy registry
│   │   └── governanceDiagnostics.js    # Governance state diagnostics
│   ├── utils/
│   │   ├── socFunctions.js             # Cloud Function client wrappers
│   │   ├── incidentStateGuard.js       # Client-side UX state mirror
│   │   ├── slaEngine.js               # Centralized SLA computation
│   │   ├── roleEngine.js              # Role hierarchy utilities
│   │   ├── normalizeRole.js           # Role normalization
│   │   ├── riskEngine.js              # Risk scoring utilities
│   │   ├── fatigueEngine.js           # Analyst workload tracking
│   │   └── analyticsEngine.js         # Platform analytics
│   └── components/
│       ├── AnalyticsPanel.jsx
│       ├── InvestigationPanel.jsx
│       └── CollaborationPanel.jsx
├── functions/
│   ├── index.js                        # Function exports + global config
│   └── socActions.js                   # All security-enforced Cloud Function logic
├── tests/
│   ├── auth.spec.js
│   ├── l1-flow.spec.js
│   ├── l2-flow.spec.js
│   ├── ir-flow.spec.js
│   ├── manager-flow.spec.js
│   ├── escalation-flow.spec.js
│   ├── containment-flow.spec.js
│   ├── governance.spec.js
│   ├── full-lifecycle.spec.js
│   ├── edge-cases.spec.js
│   ├── regression.spec.js
│   └── security.spec.js
├── firestore.rules
├── firestore.indexes.json
└── firebase.json
```

---

## 🚦 Getting Started

### Prerequisites
- Node.js 18+
- Firebase CLI (`npm install -g firebase-tools`)
- A Firebase project with Firestore, Functions, and Authentication enabled

> ⚠️ Full RBAC enforcement requires Firebase setup. This project prioritizes secure deployment over plug-and-play simplicity.

### Setup

```bash
# Clone the repository
git clone https://github.com/cc505652/explain-sec.git
cd explain-sec

# Install frontend dependencies
npm install

# Install Cloud Functions dependencies
cd functions && npm install && cd ..

# Set your Firebase project
firebase use --add

# Set the Gemini API key secret (for AI narration)
firebase functions:secrets:set GEMINI_API_KEY

# Deploy everything
firebase deploy
```

### Local Development

```bash
# Start the frontend dev server
npm run dev

# Emulate Cloud Functions locally (separate terminal)
firebase emulators:start --only functions,firestore
```

### Run Tests

```bash
npx playwright test --workers=1
```

---

## 🧪 Current Status

**Version:** v1.0.0  
**Phase:** 1 — Final Stable

| Component | Status |
|----------|--------|
| Frontend dashboards (7 roles) | ✅ Complete |
| Cloud Functions (11 functions) | ✅ Complete |
| Server-enforced RBAC | ✅ Complete |
| Incident lifecycle state machine | ✅ Complete |
| Governance engine | ✅ Complete |
| Threat Hunt workflow | ✅ Complete |
| PIR workflow | ✅ Complete |
| RCA workflow | ✅ Complete |
| Risk Acceptance workflow | ✅ Complete |
| Timeline engine | ✅ Complete |
| Audit engine | ✅ Complete |
| SLA engine | ✅ Complete |
| Permission engine (ABAC) | ✅ Complete |
| Playwright test suite | ✅ 465/465 passing |
| Governance lock system | ✅ Complete |
| Idempotency guards | ✅ Complete |
| AI narration (Gemini) | 🔜 Planned |

---

## 🔮 Roadmap

### Phase 2 — Architect Layer
- Wire `permissions.js` into component routing (replacing inline role checks)
- Centralized Policy Engine with Firestore-backed dynamic overrides
- Multi-Tenant Architecture (org-level isolated SOC environments)
- Secure API Gateway Layer (token auth, rate limiting, audit tracing)
- Identity Federation Simulation (SSO, MFA flows, session governance)
- Risk Scoring Engine (dynamic severity, analyst confidence, escalation frequency)
- Zero Trust Segmentation Logic (trust elevation, privileged action gating)

### Phase 3 — Cloud Security Architecture
- AWS Security Simulation (IAM policy simulation, CloudTrail-style events, GuardDuty-style alerts)
- Azure / Entra ID integration concepts (conditional access, PIM simulation)
- Kubernetes Security Simulation (cluster alerts, RBAC abuse detection)
- Attack Path Visualization (lateral movement graphs, trust chain mapping)
- Threat Intelligence Pipeline (IOC ingestion, enrichment, ATT&CK correlation)

### Phase 4 — Elite Security Platform
- SOAR automation engine
- AI-assisted triage and investigation
- Detection rule builder (Sigma/YARA support)
- Security data lake simulation
- Purple-team simulation environment
- SIEM query engine

---

## 📄 License

MIT — see [LICENSE](./LICENSE) for details.

---

<div align="center">
  <sub>Built with React · Firebase · Cloud Functions · Security Architecture Principles</sub><br/>
  <sub>ExplainSec v1.0.0 — Security Platform Foundation. Every write is accountable.</sub>
</div>
