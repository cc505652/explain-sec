# 📋 ExplainSec Phase 2 — Comprehensive Test Expansion Plan

> **Document Status**: Active Plan  
> **Target Release**: ExplainSec v2.0.0 Enterprise Verification  
> **Date**: 2026-08-01  

---

## 🎯 1. Existing Coverage & Expansion Audit

| Subsystem Module | Current Test File | Current Test Count | Expansion Target | Key Missing Capabilities to Test | Priority |
|---|---|---|---|---|---|
| **Enterprise Generator** | `tests/generator/enterpriseGenerator.spec.js` | 4 | 25+ | All 7 simulation profiles, 23+ log source providers, noise ratio limits, seed PRNG determinism, invalid config, pause/resume, event ordering | P0 |
| **Attack Composer** | `tests/attackComposer/attackComposer.spec.js` | 4 | 25+ | All 6 Attacker Profiles, FSM stage transitions, branching, Defender blocks, abandoned/failed chains, concurrent FSMs, IOC generation | P0 |
| **Telemetry Bus** | `tests/telemetry/telemetryBus/telemetryBus.spec.js` | 4 | 15+ | Pub/sub, rolling 100 live buffer, session buffer, subscriber cleanup, backpressure, event replay, duplicate suppression | P0 |
| **Telemetry Orchestrator** | `tests/telemetry/orchestrator/orchestrator.spec.js` | 2 | 15+ | All 8 pipeline context stages, execution ordering, context mutation, error recovery, malformed payload handling | P0 |
| **Detection Engine** | `tests/telemetry/detection/detectionEngine.spec.js` | 2 | 20+ | Individual detection rules (LSASS access, encoded PS, Kerberoast, etc.), false positives, false negatives, invalid payload handling | P0 |
| **Entity Registry** | `tests/entityRegistry/entityRegistry.spec.js` | 3 | 20+ | All 8 entity types (Host, User, IP, Hash, IOC, Process, Email, Cloud), relationship linking, reverse lookup, sub-ms lookup latency | P0 |
| **Correlation Engine** | `tests/correlation/emergentCorrelation.spec.js` | 2 | 30+ | 15 dimensions, sliding windows (5m, 10m, 30m), hypothesis confidence progression, cluster lifecycle, cross-host & cross-user linking | P0 |
| **Risk Engine** | `tests/telemetry/risk/risk.spec.js` | 2 | 15+ | Asset criticality weighting, severity weights, tactic count multipliers, score clamping strictly to [0, 100], determinism | P0 |
| **Qualification Engine** | `tests/telemetry/qualification/qualification.spec.js` | 2 | 15+ | Threshold crossing (>60 risk), noise suppression (<40 risk), single critical alert exception, campaign qualification | P0 |
| **Canonical Incident Builder** | `tests/correlationEngine.spec.js` | 5 | 15+ | Phase 1 schema fields, origin cluster ID, provenance metadata, status history structure, role visibility flags | P0 |
| **Session Manager** | `tests/telemetry/session/session.spec.js` | 2 | 15+ | Simulation UUID, session vs lifetime stats aggregation, 3-tier event storage isolation, Firestore session archive | P0 |
| **Security Console UI** | `tests/ui/consoleUI.spec.js` | 3 | 20+ | Tab navigation (`Live Events`, `Event History`, `Queue`, `Stats`), Detection Analytics metrics, Telemetry Health Header, drawer trigger | P0 |
| **Full SOC Workflow** | `tests/workflow/fullSOCWorkflow.spec.js` | 2 | 15+ | Telemetry event ➔ Emergent Correlation ➔ Qualified Cluster ➔ Canonical Incident ➔ Firestore ➔ L1 ➔ L2 ➔ Manager | P0 |
| **Performance & Stress** | `tests/performance/performanceStress.spec.js` | 2 | 10+ | Ingestion throughput (1,000 evts < 500ms), entity lookup scalability (<10ms), memory stability | P0 |
| **Accessibility & A11y** | `tests/accessibility/a11y.spec.js` | 1 | 10+ | ARIA landmarks, button focus, modal keyboard focus traps, ESC key handling | P1 |

---

## 📈 2. Suite Expansion Action Plan

1. **Enterprise Generator Expansion (`enterpriseGenerator.spec.js`)**: Add comprehensive tests for every profile (`SmallOffice`, `MidEnterprise`, `Fortune500`, `Government`, `Hospital`, `University`, `Bank`), 23+ providers, seed reset, profile switching, and stats aggregation.
2. **Attack Composer Expansion (`attackComposer.spec.js`)**: Add comprehensive tests for every adversary profile (`APT`, `Ransomware`, `ScriptKiddie`, `Insider`, `CommodityMalware`, `CloudAttacker`), state machine stage progression (`InitialAccess` ➔ `Execution` ➔ `CredentialAccess` ➔ `Persistence` ➔ `Discovery` ➔ `LateralMovement` ➔ `Exfiltration`), Defender blocks, and abandoned chains.
3. **Detection Engine Expansion (`detection.spec.js`)**: Add comprehensive single-event detection rule tests covering LSASS access, encoded PowerShell, Kerberoast, process injection, scheduled task creation, and benign process executions.
4. **Entity Registry Expansion (`entityRegistry.spec.js`)**: Add tests for Host, User, IP, Hash, IOC, Process, Email, and CloudResource entity indexing, entity-cluster linking, and query lookups.
5. **Correlation Engine Expansion (`emergentCorrelation.spec.js`)**: Add multi-event correlation tests covering 15 entity dimensions, hypothesis confidence levels, sliding time windows, and deduplication.
6. **Risk & Qualification Engine Expansion (`risk.spec.js` & `qualification.spec.js`)**: Add boundary testing for risk scoring, asset criticality weighting, and qualification threshold decisions.
7. **Session & Bus Infrastructure Expansion (`session.spec.js` & `telemetryBus.spec.js`)**: Add buffer limits, live rolling 100 window, lifetime localStorage persistence, and session archive flushes.
8. **UI & Workflow Expansion (`consoleUI.spec.js` & `fullSOCWorkflow.spec.js`)**: Add navigation tab testing, drawer triggers, quick-filter chips, and end-to-end incident queue visibility.

---

<div align="center">
  <sub>ExplainSec v2.0.0 — Test Expansion Plan. Subsystem Verification Roadmap.</sub>
</div>
