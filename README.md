# 🛡️ CampusSOC — Security Operations Center Platform

> A production-grade, full-stack Security Operations Center platform built with React and Firebase.  
> All critical incident mutations are server-side enforced — no client-side bypass is architecturally possible.

---

## 🚀 Project Overview

CampusSOC is a **full-stack SOC platform** designed to replicate enterprise-grade incident management workflows in a structured, role-controlled environment. It implements the complete lifecycle of a security incident — from initial student submission through L1 triage, L2 investigation, IR containment, to SOC Manager governance review — backed by a **server-side state machine** and **immutable audit logging**.

The platform is purpose-built around one core principle:  
> **Every security-relevant write goes through a Cloud Function. The client is untrusted.**

---

## 🧠 Key Features

### Security Architecture
- **Server-side enforced incident lifecycle** — no client can directly mutate `status`, `escalationApproved`, `assignedTo`, or any governance field
- **Centralized governance engine** — a single `governanceActions` Cloud Function dispatches all manager-level operations (SOAR-like architecture)
- **Immutable audit logging** — `statusHistory` and `investigationHistory` are write-blocked at the Firestore rules layer; only Cloud Functions (Admin SDK) can append audit entries
- **Role-validated on every request** — caller role is fetched from Firestore via Admin SDK on every function call — never trusted from the client token
- **Governance lock system** — SOC Manager can lock any incident, blocking all non-manager writes at both the rules and function layer
- **State machine enforced server-side** — all status transitions are validated against a `TRANSITIONS` map before any write commits

### Incident Workflow
- **Role-based workflow isolation** — L1 → L2 → IR → Manager forms a strict escalation ladder; each role can only interact with incidents in their assigned phase
- **Secure escalation and containment approval** — IR containment requires explicit SOC Manager approval before resolution is allowed
- **Dual containment gate** — IR submits containment, Manager reviews and either approves or rejects with a mandatory written reason
- **Threat Hunt conversion** — Manager can divert any active incident into a Threat Hunt case with full audit trail
- **Incident reopen workflow** — resolved/false-positive incidents can be reopened with server-validated state transition and justification

### Governance System
- **9 governance action types** — all routed through one authenticated, role-gated function
- **Mandatory reason enforcement** — every governance action requires a non-empty justification (≥3 characters), enforced server-side
- **SLA override with audit fields** — urgency can be force-escalated with `slaOverrideBy`, `slaOverrideAt`, and full history entry
- **Independent post-resolution workflows** — PIR, RCA, and Risk Acceptance are decoupled state branches; no forced sequencing
- **Idempotency guards** — repeated transfers or duplicate tags are rejected with `failed-precondition` before any Firestore write

### Frontend & UX
- **Role-scoped real-time dashboards** — each role sees only their relevant incident queue, powered by Firestore `onSnapshot`
- **SOC Manager Command Console** — dedicated governance control panel for cross-incident operations
- **AI-generated operations narration** — Gemini-powered weekly ops summary with key insights, SLA recommendations, and hotspot analysis
- **Glassmorphism UI** — dark-mode professional interface built for operational use

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        REACT FRONTEND                           │
│                                                                 │
│  StudentDashboard   L1Dashboard   L2Dashboard                   │
│  IRDashboard        SOCManagerDashboard   AdminDashboard        │
│  SOCManager_CommandConsole                                      │
│                                                                 │
│  ┌────────────────────────────────────┐                        │
│  │       Client-Side Wrappers         │                        │
│  │   src/utils/socFunctions.js        │                        │
│  │   callGovernanceAction()           │                        │
│  │   callApproveEscalation()          │                        │
│  │   callApproveContainment()  ...    │                        │
│  └────────────────┬───────────────────┘                        │
└───────────────────┼─────────────────────────────────────────────┘
                    │  Firebase Callable Functions (HTTPS)
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FIREBASE CLOUD FUNCTIONS                     │
│                   functions/socActions.js                       │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  governanceActions (unified dispatcher)                  │  │
│  │  ├─ OVERRIDE_DECISION      ├─ SLA_OVERRIDE               │  │
│  │  ├─ TRANSFER_OWNERSHIP     ├─ CONVERT_TO_THREAT_HUNT      │  │
│  │  ├─ REOPEN_INCIDENT        ├─ REJECT_CONTAINMENT          │  │
│  │  ├─ ACCEPT_RISK            ├─ TAG_RCA    ├─ TAG_PIR        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  escalateIncident    approveEscalation   denyEscalation         │
│  performContainment  approveContainment  lockIncident           │
│  updateRole          updateIncidentStatus                       │
│  generateAiOpsNarration  (Gemini 1.5 Flash)                     │
│                                                                 │
│  Security Layers applied to EVERY function:                     │
│  1. Firebase Auth token verification                           │
│  2. Role fetched from Firestore via Admin SDK                  │
│  3. Governance lock check (assertNotLocked)                    │
│  4. State machine validation (TRANSITIONS map)                 │
│  5. Mandatory reason enforcement                               │
│  6. Idempotency guard                                          │
│  7. writeAuditLog (immutable — client cannot forge)            │
└─────────────────────────────────────────────────────────────────┘
                    │  Admin SDK (bypasses Firestore rules)
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                        FIRESTORE                                │
│                                                                 │
│  /issues/{id}         Incident documents                        │
│  /users/{uid}         User profiles + roles (RBAC source)       │
│  /audit_logs/{id}     Immutable (client create/update: false)   │
│  /notifications/{id}  Role-scoped real-time alerts             │
│  /roles/{id}          Role definitions                          │
│  /config/{id}         Platform configuration                    │
└─────────────────────────────────────────────────────────────────┘
```

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| All critical writes via Cloud Functions | Eliminates client-side bypass. Admin SDK ignores rules, giving functions full authority. |
| Role stored in Firestore, read by Admin SDK | Client cannot spoof role via JWT claims or local state |
| Single `governanceActions` dispatcher | Avoids function sprawl; one auth+lock+audit pipeline shared by all governance ops |
| Firestore rules as defence layer, not primary | Functions are primary enforcement; rules add defence-in-depth for direct DB access attempts |
| State machine on server, mirrored on client | Client guard is UX only; server rejects all invalid transitions regardless |

---

## 🔐 Security Model

### Threat Model — What Was Hardened

| Attack Vector | Mitigation |
|--------------|------------|
| Client forges role in request | Role always fetched from Firestore via Admin SDK in every function. JWT role claims ignored. |
| Direct `updateDoc` to change `status` | `status` blocked in Firestore rules for all non-Admin roles. Only Cloud Functions write it. |
| Client writes fake `statusHistory` entry | `statusHistory` and `investigationHistory` explicitly removed from all client-writable field allowlists |
| Escalation bypass (write `escalationApproved: true`) | `escalationApproved` blocked in rules create/update for all non-Admin roles |
| Role self-escalation via `/users` | Role, team, analystLevel blocked in user profile self-update rule |
| Duplicate governance action spam | Idempotency guard per action: `already-exists` or `failed-precondition` thrown before any write |
| Locked incident modification | `assertNotLocked()` runs in every function; Firestore `isNotLocked()` function for direct-write paths |
| Governance field override (e.g. escalation via OVERRIDE_DECISION) | OVERRIDE_DECISION allowlist restricted to `["triageStatus", "urgency"]` only |
| Audit log injection from client | `/audit_logs` collection: `create: false`, `update: false`, `delete: false` — unconditional |

### Firestore Rules — Tier System

```
TIER 1 — Admin:           Full write access (Admin role only)
TIER 2 — SOC Manager:     Direct write limited to managerNotes, isDeleted only
                           All sensitive operations → Cloud Functions
TIER 3a — IR Team:        status + containment fields on assigned incidents, not locked
TIER 3b — Assigned Analyst: urgency, triageStatus, analystNotes on own assigned incidents
TIER 3c — Any Analyst:    Can self-claim open/unassigned incident (status: assigned only)
```

---

## 🔄 Incident Lifecycle Flow

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
      │ (L2 requests escalation)          ├──► pir_pending ──► pir_completed ──► resolved
      ▼
  escalation_approved ─────────────────── └──► risk_accepted ──► resolved
      │ (Manager approves)
      ▼
  ir_in_progress
      │
      ▼
  containment_pending ◄──── REJECT_CONTAINMENT (Manager rejects, returns to ir_in_progress)
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

### Enforcement Pipeline (every action)

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

### Post-Resolution State Branches (Decoupled)

```
resolved ──► rca_pending ──► rca_completed ──► resolved   (independent)
resolved ──► pir_pending ──► pir_completed ──► resolved   (independent)
resolved ──► risk_accepted ──► resolved                   (independent)
```

PIR, RCA, and Risk Acceptance are fully decoupled — no forced sequencing between them.

---

## 📊 Dashboards Overview

### 🟡 L1 Analyst Dashboard
- View and self-claim open incidents from the live queue
- Update triage status, classification, and analyst notes
- Submit escalation requests to SOC Manager queue
- All writes scoped to own assigned incidents only

### 🟠 L2 Analyst Dashboard
- Escalated incident investigation queue
- Can request escalation to IR Team via `escalateIncident` Cloud Function
- Investigation notes and evidence tracking
- Confirms threat classification before escalation

### 🔴 IR Team Dashboard
- Containment-focused view of IR-assigned incidents
- Submit containment actions via `performContainment` Cloud Function
- `readyForManagerReview` flag triggers Manager approval queue
- Cannot approve own containment (requires Manager gate)

### 🟣 SOC Manager Dashboard
- Full governance control panel across all active incidents
- Approve/deny escalations and containment requests
- Access to all 9 `governanceActions` operation types
- Lock/unlock incidents for governance holds
- View real-time escalation and containment approval queues

### 🔷 Admin Dashboard
- User management: create, assign, update roles
- RBAC configuration via `updateRole` Cloud Function
- Full incident visibility across all queues

### 🖥️ Command Console
- Dedicated SOC Manager operational view
- Cross-incident aggregated statistics
- AI-generated ops narration (Gemini 1.5 Flash)
- SLA breach indicators and hotspot tracking

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
| threat_hunt → open (exit path) | ✅ WORKING |
| PIR independent of RCA | ✅ WORKING |
| RCA independent of PIR | ✅ WORKING |
| Risk Acceptance independent of PIR/RCA | ✅ WORKING |

---

## 📌 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, React Router v6, Vite |
| **State / Real-time** | Firestore `onSnapshot` (no Redux needed) |
| **Backend Functions** | Firebase Cloud Functions v2 (Node.js 24) |
| **Database** | Cloud Firestore (NoSQL) |
| **Auth** | Firebase Authentication |
| **AI Narration** | Google Gemini 1.5 Flash (via `@google/generative-ai`) |
| **Security** | Firebase Admin SDK, Firestore Security Rules |
| **Deployment** | Firebase Hosting + Cloud Functions (asia-south1) |
| **Styling** | Vanilla CSS, glassmorphism design system |

---

## 📈 What Makes This System Unique

### 1. Zero-Trust Client Architecture
Every security decision is made on the server. The client is treated as untrusted — it can read data it's authorised to see and submit requests, but it cannot directly mutate any field that influences security posture, workflow state, or audit records.

### 2. Single Governance Dispatcher
Rather than proliferating Cloud Functions (one per action), all 9 manager-level operations share a single authenticated, audited, lock-checked pipeline via `governanceActions`. This mirrors SOAR (Security Orchestration, Automation and Response) design principles.

### 3. Decoupled Post-Incident Branches
PIR (Post Incident Review), RCA (Root Cause Analysis), and Risk Acceptance are independent state machine branches from `resolved`. They do not force each other — an incident can be PIR-tagged without going through RCA, preventing both workflow bottlenecks and state machine deadlocks.

### 4. Defence-in-Depth (Three Layers)
```
Layer 1: UI guards       (UX only — not trusted)
Layer 2: Firestore rules (field-level ACL — defence in depth)
Layer 3: Cloud Functions (primary enforcement — authoritative)
```
An attacker would need to bypass all three simultaneously, and Layer 3 always runs Admin SDK which is immune to Firestore rules.

### 5. Immutable Forensic Trail
`statusHistory` and `auditLog` entries are written exclusively by Cloud Functions using `FieldValue.arrayUnion` and direct Admin SDK writes respectively. No client path exists to forge, modify, or delete entries. This makes the audit trail forensically reliable for post-incident review.

### 6. Governance Lock
SOC Manager can place a governance hold on any incident, freezing all analyst and IR writes at both the rules layer (`isNotLocked()`) and the function layer (`assertNotLocked()`). This prevents in-flight modifications during sensitive review phases.

---

## 🗂 Project Structure

```
/
├── src/
│   ├── StudentDashboard.jsx
│   ├── AnalystDashboard.jsx            # L1 / L2
│   ├── IRDashboard.jsx
│   ├── SOCManagerDashboard.jsx         # Governance control panel
│   ├── SOCManager_CommandConsole.jsx   # Ops overview + AI narration
│   ├── AdminDashboard.jsx
│   ├── firebase.js                     # Firebase initialisation
│   └── utils/
│       ├── socFunctions.js             # All Cloud Function client wrappers
│       └── incidentStateGuard.js       # Client-side UX state mirror
├── functions/
│   ├── index.js                        # Function exports + global config
│   └── socActions.js                   # All security-enforced CF logic
├── firestore.rules                     # Field-level ACL rules
├── firestore.indexes.json
└── firebase.json
```

---

## 🚦 Getting Started

### Prerequisites
- Node.js 18+
- Firebase CLI (`npm install -g firebase-tools`)
- A Firebase project with Firestore, Functions, and Authentication enabled

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/campussoc.git
cd campussoc

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

---

## 📄 License

MIT — see [LICENSE](./LICENSE) for details.

---

<div align="center">
  <sub>Built with Firebase · React · Cloud Functions · Gemini AI</sub><br/>
  <sub>Designed for operational use. Every write is accountable.</sub>
</div>
