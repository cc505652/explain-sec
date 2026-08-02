# 🛡️ ExplainSec — Security Operations Platform (Phase 1 Archival Copy)

> Archived copy of ExplainSec Phase 1 documentation (v1.0.0).

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

## 🏗 Architecture (Phase 1)

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
│  governanceActions (unified dispatcher)                         │
│  escalateIncident    approveEscalation   denyEscalation         │
│  performContainment  approveContainment  lockIncident           │
│  updateRole          updateIncidentStatus                       │
└─────────────────────────────────────────────────────────────────┘
                    │  Admin SDK
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                        FIRESTORE                                │
│                                                                 │
│  /issues/{id}            Incident documents                     │
│  /incident_timeline/{id} Immutable chronological event log      │
│  /users/{uid}            User profiles + roles (RBAC source)    │
│  /audit_logs/{id}        Immutable audit logs                   │
└─────────────────────────────────────────────────────────────────┘
```
