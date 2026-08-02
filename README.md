# 🛡️ ExplainSec — Enterprise Security Operations & Dynamic Telemetry Platform

> A production-grade Security Operations Center (SOC) platform and dynamic enterprise telemetry simulation engine modeling real-world incident response, 15-dimension emergent correlation, state-machine adversary composition, entity relationship tracking, and server-enforced governance.

![version](https://img.shields.io/badge/version-v2.0.0-blue)
![phase](https://img.shields.io/badge/phase--2-operational%20complete-brightgreen)
![tests](https://img.shields.io/badge/tests-1188%2F1188-brightgreen)
![security](https://img.shields.io/badge/security-server%20enforced-red)
![architecture](https://img.shields.io/badge/architecture-SOC%20%2B%20SIEM%20Telemetry-blueviolet)
![browsers](https://img.shields.io/badge/browsers-chromium%20%7C%20firefox%20%7C%20webkit-orange)
![coverage](https://img.shields.io/badge/coverage-97.2%25%20statement-brightgreen)

---

## 🚀 Project Overview

**ExplainSec** is a full-stack Security Operations Center (SOC) platform and dynamic enterprise telemetry simulation engine. It models the complete lifecycle of a security incident — from raw multi-provider log ingestion, entity linking, 15-dimension emergent correlation, and risk evolution, through to server-enforced triage, investigation, escalation, containment, threat hunting, post-incident review (PIR), and root cause analysis (RCA).

The platform operates on two core engineering principles:

> 1. **Server-Enforced Governance**: Every security-relevant write goes through a Cloud Function. The client is untrusted.
> 2. **Emergent Telemetry Correlation**: Telemetry does not replay fixed stories. An independent Enterprise Generator emits 95–98% benign operational noise across 23+ providers, while a State Machine Attack Composer simulates adversary chains. The Correlation Engine discovers attacks dynamically via shared entities and risk progression — without hardcoded campaign identifiers.

Most security projects stop at detection. ExplainSec starts where detection ends:

- Who is authorized to act, and at what point in the lifecycle?
- Which state transitions are valid, and who can trigger them?
- How is every decision recorded, audited, and made forensically reliable?
- How does a SOC team formally review, learn from, and close an incident?
- How does a SIEM-scale telemetry engine generate realistic enterprise noise and emergent attack signals?

---

## 🎯 Why This Project Exists

Real SOC operations involve layered workflows that most security tooling either ignores or simplifies beyond recognition. ExplainSec was built to model the full operational picture — from raw telemetry to governance:

```
Raw Enterprise Telemetry (23+ Providers)
    ↓
8-Stage Orchestration Pipeline
    ↓
15-Dimension Emergent Correlation + Entity Registry
    ↓
Dynamic Risk Evolution  R ∈ [0, 100]
    ↓
Qualified Incident Creation (Canonical Phase 1 Document)
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

Every stage has defined role boundaries, valid transitions, mandatory justifications, and immutable audit records.

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

## 🏗 High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                             ENTERPRISE TELEMETRY ENGINE                                 │
│                                                                                         │
│  ┌──────────────────────────────┐              ┌─────────────────────────────────────┐  │
│  │    Enterprise Generator      │              │       Dynamic Attack Composer       │  │
│  │ (95–98% Benign Noise Model)  │              │    (0–5 Adversary FSM Chains)       │  │
│  │ 23+ Providers (Sysmon, AD,   │              │ Attacker Profiles (APT, Ransomware, │  │
│  │ CloudTrail, Entra ID, etc.)  │              │ Script Kiddie, Insider, etc.)       │  │
│  └──────────────┬───────────────┘              └──────────────────┬──────────────────┘  │
│                 │                                                 │                     │
│                 └───────────────────────┬─────────────────────────┘                     │
│                                         │ SecurityEvent Payload                         │
│                                         ▼                                               │
│                                 ┌──────────────┐                                        │
│                                 │ TelemetryBus │                                        │
│                                 └──────┬───────┘                                        │
└────────────────────────────────────────┼────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                             TELEMETRY ORCHESTRATOR PIPELINE                             │
│                                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────────────────┐  │
│  │ Standardizer │ ──►│  Enrichment  │ ──►│Classification│ ──►│   Detection Engine    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘    └───────────┬───────────┘  │
│                                                                          │              │
│                                                                          ▼              │
│  ┌──────────────────────┐    ┌──────────────────────┐    ┌───────────────────────────┐  │
│  │ Qualification Engine │◄───│  Risk Evolution      │◄───│  Emergent Correlation     │  │
│  └──────────┬───────────┘    │  (Dynamic R∈[0,100]) │    │  (15-Dimension + Entity)  │  │
│             │                └──────────────────────┘    └───────────▲───────────────┘  │
│             │ Qualified Cluster                                      │                  │
│             ▼                                                        │ Entity Index     │
│  ┌─────────────────────────────────────┐                  ┌──────────┴──────────┐       │
│  │     Canonical Incident Builder      │                  │   Entity Registry   │       │
│  │  (Builds Phase 1 Compliant Document)│                  │ (Host, User, IP,    │       │
│  └──────────────────┬──────────────────┘                  │ Hash, Process, etc.)│       │
└─────────────────────┼─────────────────────────────────────└─────────────────────┘───────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                       SOC GOVERNANCE PLATFORM (Phase 1 Foundation)                      │
│                                                                                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │                        REACT FRONTEND                                             │  │
│  │  StudentDashboard   L1Dashboard    L2Dashboard    IRDashboard                     │  │
│  │  ThreatHunterDashboard   SOCManagerDashboard   AdminDashboard                     │  │
│  │  SOCManager_CommandConsole   SecurityOperationsConsole                            │  │
│  │                                                                                   │  │
│  │  ┌────────────────────────────────────┐                                           │  │
│  │  │       Client-Side Wrappers         │                                           │  │
│  │  │   src/utils/socFunctions.js        │                                           │  │
│  │  │   callGovernanceAction()           │                                           │  │
│  │  │   callApproveEscalation()          │                                           │  │
│  │  │   callApproveContainment()  ...    │                                           │  │
│  │  └────────────────┬───────────────────┘                                           │  │
│  └───────────────────┼───────────────────────────────────────────────────────────────┘  │
│                      │  Firebase Callable Functions (HTTPS)                             │
│                      ▼                                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │                    FIREBASE CLOUD FUNCTIONS                                       │  │
│  │                   functions/socActions.js                                         │  │
│  │                                                                                   │  │
│  │  ┌────────────────────────────────────────────────────────────────────────────┐   │  │
│  │  │  governanceActions (unified dispatcher)                                    │   │  │
│  │  │  ├─ OVERRIDE_DECISION      ├─ SLA_OVERRIDE    ├─ TRANSFER_OWNERSHIP        │   │  │
│  │  │  ├─ CONVERT_TO_THREAT_HUNT ├─ REOPEN_INCIDENT ├─ REJECT_CONTAINMENT        │   │  │
│  │  │  ├─ ACCEPT_RISK            ├─ TAG_RCA          ├─ TAG_PIR                  │   │  │
│  │  └────────────────────────────────────────────────────────────────────────────┘   │  │
│  │                                                                                   │  │
│  │  escalateIncident    approveEscalation   denyEscalation                           │  │
│  │  performContainment  approveContainment  lockIncident                             │  │
│  │  updateRole          updateIncidentStatus                                         │  │
│  │                                                                                   │  │
│  │  Security layers applied to EVERY function:                                       │  │
│  │  1. Firebase Auth token verification                                              │  │
│  │  2. Role fetched from Firestore via Admin SDK                                     │  │
│  │  3. Governance lock check (assertNotLocked)                                       │  │
│  │  4. State machine validation (TRANSITIONS map)                                    │  │
│  │  5. Mandatory reason enforcement                                                  │  │
│  │  6. Idempotency guard                                                             │  │
│  │  7. writeAuditLog (immutable — client cannot forge)                               │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
│                      │  Admin SDK (bypasses Firestore rules)                            │
│                      ▼                                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │                        FIRESTORE                                                  │  │
│  │                                                                                   │  │
│  │  /issues/{id}                  Canonical Incidents (written by Incident Generator)│  │
│  │  /incident_timeline/{id}       Immutable Chronological Event Log                  │  │
│  │  /audit_logs/{id}              Immutable Forensic Audit Log                       │  │
│  │  /telemetry_simulations        Firestore Simulation Archive Metadata              │  │
│  │  /telemetry_simulation_events  Persisted Historical Telemetry Stream              │  │
│  │  /users/{uid}                  User profiles + roles (RBAC source)                │  │
│  │  /notifications/{id}           Role-scoped real-time alerts                       │  │
│  │  /roles/{id}                   Role definitions                                   │  │
│  │  /config/{id}                  Platform configuration                             │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| All critical writes via Cloud Functions | Eliminates client-side bypass. Admin SDK ignores rules, giving functions full authority. |
| Role stored in Firestore, read by Admin SDK | Client cannot spoof role via JWT claims or local state. |
| Single `governanceActions` dispatcher | Avoids function sprawl; one auth + lock + audit pipeline shared by all governance ops — mirrors SOAR architecture. |
| Firestore rules as defence layer, not primary | Functions are primary enforcement; rules add defence-in-depth for direct DB access attempts. |
| State machine on server, mirrored on client | Client guard is UX only; server rejects all invalid transitions regardless. |
| Write-split pattern for Firestore updates | Splits scalar writes from `arrayUnion` writes to eliminate read-modify-write contention under concurrent analyst load. |
| `actorRole` always explicit in audit events | Prevents implicit role inference bugs — every audit record carries the verified role at time of action. |
| 95–98% benign noise model | Real enterprise SIEMs are dominated by legitimate operational traffic. A realistic simulation must model the noise, not just the signal. |
| Emergent correlation — no hardcoded campaign IDs | Real attacks do not include a `campaign_id` field. The correlation engine discovers attacks via shared entities and risk trajectory, the same way a real SIEM must. |
| Seeded PRNG for deterministic replay | Simulation output is fully reproducible for testing and debugging — `seededRandom.js` ensures deterministic event sequences given the same seed. |
| Canonical Incident Builder enforces Phase 1 schema | Every telemetry-sourced incident is structurally identical to a manually submitted incident, ensuring the SOC workflow layer operates uniformly regardless of incident origin. |

---

## ⚡ Telemetry Pipeline Details

Every security log flows through an 8-stage pipeline coordinated by `TelemetryOrchestrator`:

```
Generator ──► Standardizer ──► Enrichment ──► Classification ──► Detection ──► Correlation ──► Risk Evolution ──► Qualification ──► Incident
```

| Stage | Subsystem | Function |
|---|---|---|
| **1. Ingestion** | `EnterpriseGenerator` / `AttackComposer` | Emits `SecurityEvent` schema v2.0 payloads into `TelemetryBus`. |
| **2. Standardization** | `telemetryOrchestrator` | Validates schema integrity, formats timestamps to ISO 8601, attaches unique event IDs. |
| **3. Enrichment** | `enrichmentEngine.js` | Enriches endpoint criticality, department metadata, user principals, and threat intel. |
| **4. Classification** | `eventClassifier.js` | Categorizes telemetry (execution, authentication, network, cloud, persistence) and assigns base severity. |
| **5. Detection** | `detectionEngine.js` | Evaluates single-event detection rules against threshold conditions (e.g. LSASS Access, Encoded PowerShell). |
| **6. Correlation** | `correlationEngine.js` + `entityRegistry.js` | Indexes event in `EntityRegistry` across 8 entity types and correlates using 15 dimensions without hardcoded campaign identifiers. |
| **7. Risk Evolution** | `riskEngine.js` | Recalculates dynamic risk score $R \in [0, 100]$ based on rule weight, asset criticality, tactic count, and velocity. |
| **8. Qualification** | `qualificationEngine.js` + `incidentGenerator.js` | Qualifies clusters crossing risk/confidence thresholds, calls `buildCanonicalIncident()`, and writes to Firestore `/issues`. |

---

## ⚙️ Core Telemetry Subsystems

### 1. Simulation Profiles (`simulationProfiles.js`)

Configures enterprise scale, log provider weights, user domains, and threat likelihoods:

| Profile | Endpoints | Stack | Threat Landscape |
|---|---|---|---|
| **Small Office / Branch** | 25 | Basic Defender & Firewall | Low complexity |
| **Mid Enterprise** | 250 | Hybrid cloud/on-prem, Entra ID, Sysmon, VPN & Proxy | Moderate |
| **Fortune 500 Global** | 1,000+ | Multi-cloud AWS/Azure, EDR, Key Vault, WAF, M365 | High |
| **Government Agency** | 500 | Active Directory DS, high audit compliance | Nation-state focused |
| **Healthcare System** | 300 | Medical devices, legacy Windows, EHR servers | Ransomware, compliance |
| **University Campus** | 600 | BYOD, open Wi-Fi, cloud apps | Commodity threats |
| **Financial Institution** | 800 | SWIFT/PCI-DSS audit, Key Vault, strict proxy | APT, insider threat |

### 2. Attacker Profiles & State Machine FSM (`attackComposer.js` + `attackerProfiles.js`)

Simulates adversary behavior using 6 distinct profiles with unique stealth and failure parameters:

| Profile | Stealth | Failure Rate | Primary Tactics |
|---|---|---|---|
| **APT** | High | Low | Multi-stage, living-off-the-land |
| **Ransomware Crew** | Medium | Low | Credential access, lateral movement, encryption |
| **Script Kiddie** | Low | High | Noisy, tool-based, opportunistic |
| **Insider Threat** | High | Very Low | Discovery, exfiltration |
| **Commodity Malware** | Low | Medium | Automated, volume-based |
| **Cloud Attacker** | Medium | Medium | Key Vault, S3/Blob, IAM abuse |

FSM adversary stages:

```
InitialAccess ──► Execution ──► CredentialAccess ──► Persistence ──► Discovery ──► LateralMovement ──► Exfiltration
                                                          │
                                              (Defender block → abort chain)
                                              (Random failure → mid-chain abandon)
```

Executes 0–5 concurrent attack chains. Simulates realistic adversary failures (e.g. Defender blocks script) and mid-attack abandonment.

### 3. Entity Registry (`entityRegistry.js`)

In-memory registry indexing 8 security entity types with relationship linking and sub-millisecond lookup:

| Entity Type | Key Attributes |
|---|---|
| **Host** | Hostname, OS, IP, Criticality |
| **User** | Username, Domain, UPN, Role |
| **IP** | Internal IP / C2 Destination IP |
| **Hash** | File SHA-256 |
| **IOC** | IP / Domain indicators |
| **Process** | Process Name, PID, Command Line |
| **Email** | Sender / Recipient UPN |
| **CloudResource** | Key Vault, S3/Blob, ARN |

### 4. 15-Dimension Emergent Correlation Engine (`correlationEngine.js`)

Correlates events without relying on hardcoded campaign IDs. Discovers attacks dynamically via:

| Dimension | Description |
|---|---|
| 1. Primary Host | Events sharing the same endpoint |
| 2. Primary User | Events sharing the same user identity |
| 3. Source IP | Same originating IP address |
| 4. Destination IP / C2 | Same destination or known C2 |
| 5. Process Lineage | Parent-child process chain |
| 6. Process Hash | Same binary SHA-256 |
| 7. IOC Indicators | Shared IP/domain indicators |
| 8. MITRE Technique ID | Same ATT&CK technique |
| 9. MITRE Tactic | Same ATT&CK tactic category |
| 10. Category | Same event classification |
| 11. Detection Rule ID | Same detection rule triggered |
| 12. Sliding Time Window | Events within 5m / 10m / 30m windows |
| 13. Asset Criticality Weight | High-criticality asset proximity |
| 14. Risk Evolution Trajectory | Rising risk score pattern |
| 15. Emergent Pattern Inference | Cross-dimension signal amplification |

**Hypothesis Confidence Progression:**

```
Single Event                    → No cluster
Low-correlation cluster         → Possible Threat Hypothesis   (25%–50%)
Multi-dimension cluster         → Likely Threat Hypothesis     (51%–85%)
High-confidence cluster (>86%)  → Confirmed Threat Hypothesis  → Qualification
```

### 5. Risk Evolution Engine (`riskEngine.js`)

Dynamic risk score calculation: $R = \text{clamp}(\sum(\text{ruleWeight} \times \text{criticalityMultiplier} \times \text{tacticCount} \times \text{velocityFactor}), 0, 100)$

Risk score strictly bounded to $R \in [0, 100]$ with deterministic output guaranteed by seeded PRNG.

### 6. Qualification Engine (`qualificationEngine.js`)

Qualification decision matrix:

| Cluster State | Risk Score | Action |
|---|---|---|
| Single benign event | < 40 | Suppressed — no incident |
| Low-correlation cluster | < 40 | Suppressed — noise |
| Multi-event cluster | 40–60 | Monitoring — not yet qualified |
| Confirmed cluster | > 60 | **Qualified → Incident Creation** |
| Single critical-severity rule hit | Any | Immediate qualification bypass |

---

## ⚙️ SOC Platform Engines (Phase 1 Foundation)

### Permission Engine (`src/security/permissions.js`)

Centralized, deny-by-default ABAC authorization layer.

- Explicit permission constants — no magic strings
- Set-based role-to-permission mapping — no numeric threshold inheritance
- Safe defaults: unknown role or permission → `false`
- `canUser(user, permission)` and `hasPermission(role, permission)` as canonical check functions
- `getPermissionMatrix()` for admin introspection and runtime RBAC audit

### Governance Engine (`functions/socActions.js` — `governanceActions`)

Single authenticated dispatcher for all SOC Manager operations. Every action passes through the same enforcement pipeline:

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

### Timeline Engine (`src/security/timelineEngine.js`)

Chronological event reconstruction for every incident. Captures:

- Status transitions, escalation events (requested, approved, denied)
- Containment events (requested, approved, rejected, executed)
- Governance events (lock, unlock, override, risk acceptance)
- Threat Hunt events (conversion, assignment, findings)
- PIR and RCA lifecycle events
- Assignment and reassignment history

All events written to flat, queryable `/incident_timeline` collection. Client writes unconditionally blocked.

### Audit Engine (`src/security/auditEngine.js`)

Immutable security event log.

- Explicit action constants — no raw strings
- Standardized event schema with validation
- Detached Firestore writes (fire-and-forget, non-blocking)
- In-memory deduplication ring buffer (16-entry, 3-second window)
- `actorRole` always explicit — never inferred
- Domain wrappers for escalation, containment, governance, and investigation events

### SLA Engine (`src/utils/slaEngine.js`)

Centralized SLA computation:

- SLA deadline calculation per incident status
- Breach detection and at-risk detection
- Time remaining / elapsed formatting
- SLA override recording with `slaOverrideBy`, `slaOverrideAt` fields

### Incident State Guard (`src/utils/incidentStateGuard.js`)

Client-side UX mirror of the server state machine. Prevents invalid transition UI from rendering — not a security control. The server independently validates all transitions.

---

## 🔐 Security Model

### Threat Model — What Was Hardened

| Attack Vector | Mitigation |
|--------------|------------|
| Client forges role in request | Role always fetched from Firestore via Admin SDK in every function. JWT role claims ignored. |
| Direct `updateDoc` to change `status` | `status` blocked in Firestore rules for all non-Admin roles. Only Cloud Functions write it. |
| Client writes fake `statusHistory` entry | `statusHistory` and `investigationHistory` explicitly removed from all client-writable field allowlists. |
| Escalation bypass (`escalationApproved: true`) | `escalationApproved` blocked in rules create/update for all non-Admin roles. |
| Role self-escalation via `/users` | Role, team, analystLevel blocked in user profile self-update rule. |
| Duplicate governance action spam | Idempotency guard per action: `already-exists` or `failed-precondition` thrown before any write. |
| Locked incident modification | `assertNotLocked()` runs in every function; Firestore `isNotLocked()` for direct-write paths. |
| Governance field override via OVERRIDE_DECISION | Allowlist restricted to `["triageStatus", "urgency"]` only. |
| Audit log injection from client | `/audit_logs`: `create: false`, `update: false`, `delete: false` — unconditional. |
| Timeline injection from client | `/incident_timeline`: client write unconditionally blocked. |
| Telemetry incident spoofing | Canonical Incident Builder runs server-side only; client has no write path to `/issues` status or history fields. |

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

An attacker must bypass all three simultaneously. Layer 3 always runs Admin SDK, immune to Firestore security rules.

---

## 🔄 Incident Lifecycle

```
[Telemetry Qualification / Student Submits]
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
L2 Analyst           SOC Manager            IR Team
    │                    │                     │
    │ escalateIncident() │                     │
    ├───────────────────►│                     │
    │                    │ approveEscalation() │
    │                    ├───────────────────► │
    │                    │  (or denyEscalation)│
    │                    │                     │ performContainment()
    │                    │ ◄────────────────── ┤
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

PIR, RCA, and Risk Acceptance are fully decoupled. An incident can be PIR-tagged without RCA, preventing both workflow bottlenecks and state machine deadlocks.

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

## 🖥️ UI Subsystems & Console Panels

### Phase 2 — Security Operations Console

| Component | File | Purpose |
|---|---|---|
| **SecurityOperationsConsole** | `SecurityOperationsConsole.jsx` | Main SOC hub — top tab navigation (`📡 Live Events`, `📋 Event History`, `🚨 Incident Queue`, `📝 Manual Reports`, `⚙️ Engine Stats`) |
| **TelemetryHealthHeader** | `TelemetryHealthHeader.jsx` | Engine status, speed, active feeds, side-by-side **Current Simulation** vs **Lifetime Cumulative** statistics with active Session ID badge |
| **DetectionAnalyticsPanel** | `DetectionAnalyticsPanel.jsx` | Live SOC metrics: Events/sec, Noise Breakdown (Benign % / Suspicious % / Malicious %), Active Adversary FSM Chains, Correlation Qualification Rate, Suppressed Event Count |
| **EventDetailsDrawer** | `EventDetailsDrawer.jsx` | 7-tab investigation panel: `PipelineStepper` → `Overview` → `Detection` → `Evidence` → `Asset` → `Correlation` → `Timeline` → `RawEvent` → `ActionBar` |
| **PipelineStepper** | `drawer/PipelineStepper.jsx` | Animated stage-by-stage pipeline visualization with 80ms staggered reveals across all 8 pipeline stages |
| **DynamicCorrelationGraph** | `drawer/DynamicCorrelationGraph.jsx` | Interactive SVG entity node graph rendered live from `EntityRegistry` data |
| **EventHistoryPanel** | `EventHistoryPanel.jsx` | Unified history with `⚡ Current Simulation` / `🗄️ Previous Simulations` toggle, quick-filter chips (Severity, Category, Source, Status), text search, and Firestore simulation cards |

**EventDetailsDrawer — 7 Investigation Tabs:**

| Tab | Contents |
|---|---|
| **Pipeline** | `PipelineStepper.jsx` — animated 8-stage pipeline visualization |
| **Overview** | Event ID, timestamp, source, provider, severity, confidence, user context |
| **Detection** | Rule metadata, author, threshold, MITRE ATT&CK technique mapping |
| **Evidence** | Command line, parent process, SHA-256 hash, registry targets, network details, IOCs |
| **Asset** | Hostname, IP, asset type, department, owner, criticality, location |
| **Correlation** | Cluster status, risk score, qualification reason, explanation bullets, Dynamic SVG Correlation Graph |
| **Timeline** | Chronological pipeline timeline + Investigation Timeline reconstruction |
| **Raw Event** | Pretty-printed JSON payload |
| **Action Bar** | Copy JSON, View MITRE, Timeline Chain, Multi-Format Export (JSON / CSV / Markdown) |

### Phase 1 — SOC Role Dashboards

| Dashboard | Purpose |
|---|---|
| **🟡 L1 Analyst Dashboard** | Triage queue, self-claim, escalation requests, analyst notes — writes scoped to own assigned incidents only |
| **🟠 L2 Analyst Dashboard** | Investigation queue, evidence tracking, threat classification, IR escalation |
| **🔴 IR Analyst Dashboard** | Containment workspace, `performContainment` Cloud Function, Manager review gate |
| **🟤 Threat Hunter Dashboard** | Threat Hunt queue, ATT&CK-mapped investigation, findings submission, approval gate |
| **🟣 SOC Manager Dashboard** | Full governance control panel — all 9 `governanceActions` types, escalation/containment approval, governance locks, PIR/RCA/risk management |
| **🖥️ Command Console** | Cross-incident operational view, SLA breach indicators, incident throughput and queue health metrics |
| **🔷 Admin Dashboard** | User management, RBAC configuration via `updateRole` Cloud Function, full incident visibility |

---

## 🧪 Validation & Security Testing

### Phase 2 — Automated Verification Metrics

| Metric | Target | Achieved | Status |
|---|---|---|---|
| **Total Automated Tests** | ≥ 50 | **1188** | ✅ PASSED |
| **Test Suite Pass Rate** | 100% | **100% (1188/1188)** | ✅ PASSED |
| **Statement Coverage** | ≥ 95.0% | **97.2%** | ✅ PASSED |
| **Branch Coverage** | ≥ 90.0% | **94.8%** | ✅ PASSED |
| **Function Coverage** | ≥ 95.0% | **98.0%** | ✅ PASSED |
| **Console Errors / React Warnings** | 0 | **0** | ✅ PASSED |
| **Firestore Unhandled Promise Rejections** | 0 | **0** | ✅ PASSED |
| **Performance Benchmark (1k events)** | < 500ms | **< 350ms** | ✅ PASSED |
| **Entity Lookup Latency** | < 10ms | **< 10ms** | ✅ PASSED |
| **Browser Targets** | Cross-browser | **Chromium + Firefox + WebKit** | ✅ PASSED |

### Phase 2 — Test Suite Breakdown

| Test Suite | Path | Tests | Browsers | Key Capabilities Verified |
|---|---|---|---|---|
| **Smoke Suite** | `tests/smoke/smoke.spec.js` | 3 | 3 | App load, routing, console error cleanliness |
| **Enterprise Generator** | `tests/generator/enterpriseGenerator.spec.js` | 4 | 3 | 23+ log providers, 7 profiles, noise ratio, seed determinism |
| **Attack Composer** | `tests/attackComposer/attackComposer.spec.js` | 9 | 3 | 6 attacker profiles, FSM progression, branching, Defender blocks |
| **Entity Registry** | `tests/entityRegistry/entityRegistry.spec.js` | 3 | 3 | 8 entity types, event/cluster linking, relationship queries |
| **Emergent Correlation** | `tests/correlation/emergentCorrelation.spec.js` | 15 | 3 | 15 dimensions, risk evolution, hypothesis confidence, deduplication, sliding windows |
| **Console UI** | `tests/ui/consoleUI.spec.js` | 3 | 3 | SOC console tabs, Detection Analytics, Health Header, profile selector |
| **Correlation Engine** | `tests/correlationEngine.spec.js` | 5 | 3 | Risk scoring bounds, seeded PRNG, canonical incident structure |
| **SOC L1 Flow** | `tests/l1-flow.spec.js` | 13 | 3 | L1 triage, claim, escalation, RBAC controls, dashboard metrics |
| **Telemetry Bus** | `tests/telemetry/telemetryBus/telemetryBus.spec.js` | 4 | 3 | Dual buffers (rolling 100 + session), event emission, stats sync |
| **Orchestrator** | `tests/telemetry/orchestrator/orchestrator.spec.js` | 2 | 3 | 8-stage pipeline execution, context flow |
| **Standardizer** | `tests/telemetry/standardizer/standardizer.spec.js` | 3 | 3 | Schema v2.0 validation, ISO timestamp, event ID attachment |
| **Enrichment** | `tests/telemetry/enrichment/enrichment.spec.js` | 2 | 3 | Asset criticality, user principal, department metadata |
| **Classifier** | `tests/telemetry/classifier/classifier.spec.js` | 2 | 3 | Category taxonomy, severity assignment |
| **Detection** | `tests/telemetry/detection/detection.spec.js` | 2 | 3 | LSASS dump, encoded PowerShell, threshold matching |
| **Qualification** | `tests/telemetry/qualification/qualification.spec.js` | 2 | 3 | Qualification decisions, noise suppression |
| **Risk** | `tests/telemetry/risk/risk.spec.js` | 2 | 3 | Dynamic risk calculation, [0,100] clamping |
| **Session** | `tests/telemetry/session/session.spec.js` | 2 | 3 | Session UUID, 3-tier storage, stats aggregation |
| **Full SOC Workflow** | `tests/workflow/fullSOCWorkflow.spec.js` | 2 | 3 | End-to-end: Telemetry → Firestore → L1 → Manager |
| **Performance Stress** | `tests/performance/performanceStress.spec.js` | 2 | 3 | 1,000 events < 500ms, entity lookup < 10ms |
| **Accessibility** | `tests/accessibility/a11y.spec.js` | 1 | 3 | ARIA landmarks, keyboard focus, ESC handlers |
| **Authentication** | `tests/auth.spec.js` | 16 | 3 | Login, logout, role routing, unauthorized access, session persistence |
| **Containment Flow** | `tests/containment-flow.spec.js` | 1 | 3 | IR containment and Manager review gate |
| **Unit Suites** | `tests/unit/*.spec.js` | 6 suites | 3 | clusterRepository, constants, correlationCluster, pipelineContext, securityEvent, seededRandom |
| **Full Lifecycle** | `tests/full-lifecycle.spec.js` | — | 3 | Complete incident lifecycle |
| **Edge Cases** | `tests/edge-cases.spec.js` | — | 3 | Boundary conditions and failure paths |
| **Regression** | `tests/regression.spec.js` | — | 3 | Cross-version regression coverage |
| **Security** | `tests/security.spec.js` | — | 3 | Attack surface validation |
| **Escalation Flow** | `tests/escalation-flow.spec.js` | — | 3 | L2 → Manager → IR escalation gate |
| **Governance** | `tests/governance.spec.js` | — | 3 | All 9 governance action types |
| **Manager Flow** | `tests/manager-flow.spec.js` | — | 3 | SOC Manager workflow paths |

### Attack Simulation Matrix (Phase 1)

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
| Telemetry qualification → canonical incident creation | ✅ WORKING |
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
| Emergent correlation → hypothesis confidence progression | ✅ WORKING |
| Seeded PRNG → deterministic replay output | ✅ WORKING |
| 1,000 events processed in < 350ms | ✅ WORKING |

---

## 📈 Why ExplainSec Stands Out

### 1. Zero-Trust Client Architecture
Every security decision is made server-side. The client can read authorized data and submit requests — it cannot directly mutate anything that influences security posture, workflow state, or audit records.

### 2. Emergent Correlation Without Campaign IDs
Real attackers do not embed a `campaign_id` in their events. ExplainSec's correlation engine discovers attacks via shared entities, technique clustering, tactic sequences, and risk trajectory — the same way a production SIEM must operate. Most security simulation tools cheat by grouping on a shared identifier field. This one doesn't.

### 3. Realistic Noise Model (95–98% Benign)
Real enterprise SIEMs process hundreds of thousands of events per day. The vast majority are legitimate operations. A simulation that only generates attacks produces an unrealistic signal-to-noise ratio unusable for analyst training or detection validation. ExplainSec models the noise first.

### 4. Single Governance Dispatcher
All 9 manager-level operations share one authenticated, audited, lock-checked pipeline via `governanceActions`. This mirrors SOAR (Security Orchestration, Automation and Response) design principles rather than proliferating individual Cloud Functions.

### 5. Decoupled Post-Incident Branches
PIR, RCA, and Risk Acceptance are independent state machine branches from `resolved`. They do not force each other — preventing both workflow bottlenecks and state machine deadlocks.

### 6. Immutable Forensic Trail
`statusHistory` and `auditLog` entries are written exclusively by Cloud Functions using `FieldValue.arrayUnion` and direct Admin SDK writes. No client path exists to forge, modify, or delete entries. The audit trail is forensically reliable.

### 7. Governance Lock
SOC Manager can place a governance hold on any incident, freezing all analyst and IR writes at both the rules layer (`isNotLocked()`) and the function layer (`assertNotLocked()`). Prevents in-flight modifications during sensitive review phases.

### 8. Write-Split Contention Handling
Combining `serverTimestamp()` with `arrayUnion()` in a single Firestore update causes read-modify-write contention under concurrent analyst load. All writes are split — scalars first, array operations second — eliminating this class of bug.

### 9. 7 Enterprise Simulation Profiles
From a 25-endpoint branch office to a 1,000+ endpoint Fortune 500 global enterprise with multi-cloud, EDR, and WAF. Each profile generates industry-specific log providers, threat likelihoods, and adversary targeting patterns.

### 10. Cross-Browser Validated at Scale
1188 tests across Chromium, Firefox, and WebKit. 97.2% statement coverage. 98.0% function coverage. Performance validated at 1,000 events processed under 350ms.

---

## 💼 Real-World Relevance

| ExplainSec Capability | Real-World Equivalent |
|----------------------|----------------------|
| 15-dimension emergent correlation | Enterprise SIEM correlation engine (Splunk UBA, Sentinel Analytics) |
| 95-98% benign noise model | Real enterprise log volume ratios in production SIEMs |
| FSM adversary profiles with failures | MITRE CALDERA adversary emulation |
| 7 simulation profiles | SOC platform demo environments (CrowdStrike, Palo Alto) |
| Approval-based containment gate | Enterprise IR approval workflows |
| Single `governanceActions` dispatcher | SOAR platform architecture (Splunk SOAR, Cortex XSOAR) |
| Immutable audit logging | ISO 27001 / SOC 2 audit trail requirements |
| Role-isolated dashboards | Tiered SOC analyst structure |
| PIR workflow | Post-incident lessons-learned process |
| RCA workflow | Root cause tracking for systemic fixes |
| Governance lock | Change freeze / CAB hold during incident review |
| Idempotency guards | Duplicate action prevention in real ITSM platforms (ServiceNow) |
| Seeded deterministic PRNG | Reproducible test environments in security lab infrastructure |

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
| **Testing** | Playwright (end-to-end, cross-browser: Chromium + Firefox + WebKit) |
| **Deployment** | Firebase Hosting + Cloud Functions (`asia-south1`) |
| **Styling** | Vanilla CSS, glassmorphism dark-mode design system |
| **AI Integration** | Google Gemini 1.5 Flash — planned expansion |

---

## 🗂 Project Structure

```
/
├── src/
│   ├── AnalystDashboard.jsx                    # L1 / L2 combined
│   ├── IRDashboard.jsx                         # IR Analyst workspace
│   ├── SOCManagerDashboard.jsx                 # Governance control panel
│   ├── SOCManager_CommandConsole.jsx           # Ops overview
│   ├── ThreatHunterDashboard.jsx               # Threat Hunt workspace
│   ├── AdminDashboard.jsx
│   ├── firebase.js
│   ├── security/
│   │   ├── permissions.js                      # Centralized ABAC permission engine
│   │   ├── auditEngine.js                      # Immutable security event logger
│   │   ├── timelineEngine.js                   # Incident timeline reconstruction
│   │   ├── policies.js                         # Governance policy registry
│   │   └── governanceDiagnostics.js            # Governance state diagnostics
│   ├── utils/
│   │   ├── socFunctions.js                     # Cloud Function client wrappers
│   │   ├── incidentStateGuard.js               # Client-side UX state mirror
│   │   ├── slaEngine.js                       # Centralized SLA computation
│   │   ├── roleEngine.js                      # Role hierarchy utilities
│   │   ├── normalizeRole.js                   # Role normalization
│   │   ├── riskEngine.js                      # Risk scoring utilities
│   │   ├── fatigueEngine.js                   # Analyst workload tracking
│   │   └── analyticsEngine.js                 # Platform analytics
│   ├── components/
│   │   ├── AnalyticsPanel.jsx
│   │   ├── InvestigationPanel.jsx
│   │   └── CollaborationPanel.jsx
│   └── components/telemetry/                  # Phase 2 telemetry UI subsystems
│       ├── SecurityOperationsConsole.jsx       # Main SOC console + tab navigation
│       ├── TelemetryHealthHeader.jsx           # Engine health + current vs lifetime stats
│       ├── DetectionAnalyticsPanel.jsx         # Live SOC metrics + FSM chain stats
│       ├── EventDetailsDrawer.jsx              # 7-tab investigation panel
│       ├── EventHistoryPanel.jsx               # Current + previous simulations browser
│       ├── GeneratorControls.jsx              # Simulation profile selector + controls
│       └── drawer/
│           ├── PipelineStepper.jsx             # Animated 8-stage pipeline visualization
│           └── DynamicCorrelationGraph.jsx     # Interactive SVG entity node graph
├── src/telemetry/                              # Phase 2 telemetry engine
│   ├── telemetryBus.js                         # Pub/sub event broker, dual buffers
│   ├── orchestrator/
│   │   └── telemetryOrchestrator.js            # 8-stage pipeline conductor
│   ├── types/
│   │   └── securityEvent.js                    # Schema v2.0, standardizer
│   ├── enrichment/
│   │   └── enrichmentEngine.js
│   ├── classifier/
│   │   └── classificationEngine.js
│   ├── detection/
│   │   └── detectionEngine.js
│   ├── correlator/
│   │   ├── correlationEngine.js                # 15-dimension emergent correlation
│   │   ├── entityRegistry.js                   # 8-type entity index
│   │   ├── riskEngine.js                       # Dynamic risk R∈[0,100]
│   │   └── qualificationEngine.js              # Incident qualification logic
│   ├── generator/
│   │   ├── enterpriseGenerator.js              # 23+ provider benign noise model
│   │   ├── simulationProfiles.js               # 7 enterprise scale presets
│   │   ├── canonicalIncidentBuilder.js         # Phase 1 compliant incident factory
│   │   └── incidentGenerator.js                # Firestore write + audit trail
│   ├── campaigns/
│   │   ├── attackComposer.js                   # FSM adversary chain executor
│   │   └── attackerProfiles.js                 # 6 adversary profile definitions
│   ├── session/
│   │   └── telemetrySessionManager.js          # Session UUID, 3-tier storage, archive
│   └── utils/
│       └── seededRandom.js                     # Deterministic PRNG
├── functions/
│   ├── index.js                                # Function exports + global config
│   └── socActions.js                           # All security-enforced Cloud Function logic
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
│   ├── security.spec.js
│   ├── correlationEngine.spec.js
│   ├── smoke/smoke.spec.js
│   ├── generator/enterpriseGenerator.spec.js
│   ├── attackComposer/attackComposer.spec.js
│   ├── entityRegistry/entityRegistry.spec.js
│   ├── correlation/emergentCorrelation.spec.js
│   ├── ui/consoleUI.spec.js
│   ├── telemetry/
│   │   ├── telemetryBus/telemetryBus.spec.js
│   │   ├── orchestrator/orchestrator.spec.js
│   │   ├── standardizer/standardizer.spec.js
│   │   ├── enrichment/enrichment.spec.js
│   │   ├── classifier/classifier.spec.js
│   │   ├── detection/detection.spec.js
│   │   ├── qualification/qualification.spec.js
│   │   ├── risk/risk.spec.js
│   │   ├── session/session.spec.js
│   │   └── ...
│   ├── unit/
│   │   ├── clusterRepository.spec.js
│   │   ├── constants.spec.js
│   │   ├── correlationCluster.spec.js
│   │   ├── pipelineContext.spec.js
│   │   ├── securityEvent.spec.js
│   │   └── seededRandom.spec.js
│   ├── workflow/fullSOCWorkflow.spec.js
│   ├── performance/performanceStress.spec.js
│   └── accessibility/a11y.spec.js
├── firestore.rules
├── firestore.indexes.json
└── firebase.json
```

---
## 🚀 Project Availability

ExplainSec is currently released as a portfolio and research project.

The public repository is intended to showcase:

- Enterprise-grade SOC architecture
- Dynamic telemetry simulation
- Emergent correlation engine
- Server-enforced governance model
- System design and implementation
- Automated verification

The complete production environment depends on Firebase infrastructure, Cloud Functions, Firestore configuration, authentication, and supporting services that are intentionally not packaged as a one-command deployment.

Documentation, architecture, source code, screenshots, and automated test results are provided to demonstrate the platform's capabilities.

---

## 🧪 Current Status

**Version:** v2.0.0
**Phase 2:** Operational Complete

| Component | Status |
|----------|--------|
| Enterprise Generator (23+ providers, 7 profiles) | ✅ Complete |
| Dynamic Attack Composer (6 FSM adversary profiles) | ✅ Complete |
| TelemetryBus (dual buffer pub/sub) | ✅ Complete |
| 8-Stage Telemetry Orchestrator Pipeline | ✅ Complete |
| 15-Dimension Emergent Correlation Engine | ✅ Complete |
| Entity Registry (8 entity types) | ✅ Complete |
| Dynamic Risk Engine R∈[0,100] | ✅ Complete |
| Qualification Engine | ✅ Complete |
| Canonical Incident Builder (Phase 1 compliant) | ✅ Complete |
| SecurityOperationsConsole + all telemetry UI panels | ✅ Complete |
| EventDetailsDrawer (7-tab investigation panel) | ✅ Complete |
| DynamicCorrelationGraph (interactive SVG) | ✅ Complete |
| TelemetrySessionManager (3-tier storage, archive) | ✅ Complete |
| Playwright test suite (1188 tests, 3 browsers) | ✅ 1188/1188 passing |
| Statement coverage | ✅ 97.2% |
| Branch coverage | ✅ 94.8% |
| Function coverage | ✅ 98.0% |
| Frontend dashboards (7 roles) | ✅ Complete |
| Cloud Functions (11 functions) | ✅ Complete |
| Server-enforced RBAC | ✅ Complete |
| Incident lifecycle state machine | ✅ Complete |
| Governance engine (9 action types) | ✅ Complete |
| Threat Hunt workflow | ✅ Complete |
| PIR workflow | ✅ Complete |
| RCA workflow | ✅ Complete |
| Risk Acceptance workflow | ✅ Complete |
| Timeline engine | ✅ Complete |
| Audit engine | ✅ Complete |
| SLA engine | ✅ Complete |
| Permission engine (ABAC) | ✅ Complete |
| Governance lock system | ✅ Complete |
| Idempotency guards | ✅ Complete |
| AI narration (Gemini) | 🔜 Planned |

---

## 🔮 Roadmap

### Phase 3 — SIEM Connectors & Cloud Security Architecture

- **SecRule Integration**: Detection Rule Studio — author rules in the SecRule vendor-neutral detection language, compile to Splunk SPL / Microsoft KQL / Elastic ES|QL / Sigma / Chronicle YARA-L directly within ExplainSec
- **Sentrix SIEM Integration**: Ingest real Sentrix SIEM alerts directly into `TelemetryBus`
- **Syslog & REST Connectors**: Direct HTTP/Syslog ingestion endpoint for external network appliances
- **AWS CloudTrail Real Ingestion**: Ingest live CloudTrail JSON events into `EntityRegistry`
- **Azure / Entra ID Simulation**: Conditional access, privileged identity management simulation
- **Attack Path Visualization**: Upgrade SVG correlation graph to D3/React Flow with interactive lateral movement chains
- **Threat Intelligence Pipeline**: IOC ingestion, enrichment, ATT&CK correlation

### Phase 4 — Elite Security Platform

- SOAR automation engine with playbook execution
- AI-assisted triage and investigation (Gemini integration)
- Detection engineering lab
- Security data lake simulation
- Purple-team simulation environment
- Multi-tenant SOC architecture

---

## 📄 License

MIT — see [LICENSE](./LICENSE) for details.

---

<div align="center">
  <sub>Built with React 18 · Firebase · Cloud Functions · Entity Registry Architecture</sub><br/>
  <sub>ExplainSec v2.0.0 — Security Operations Platform & Telemetry Simulation Engine. Every write is accountable.</sub>
</div>
