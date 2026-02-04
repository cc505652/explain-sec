# EXPLAIN-SEC Privacy Model

EXPLAIN-SEC is built on the principle that **security must not come at the cost of user privacy**.  
The system enforces privacy by design through strict data minimization, controlled processing, and role-based visibility.

This document outlines what data is handled, how it is protected, and what boundaries are enforced.

---

## 🧠 Privacy Philosophy

EXPLAIN-SEC follows four foundational privacy commitments:

1. **Data Minimization** — Only the minimum data required for risk assessment is processed.
2. **Purpose Limitation** — Data is used strictly for security threat detection and awareness.
3. **No Surveillance** — The system does not monitor or profile individual users.
4. **Transparency** — System decisions are explainable without exposing sensitive information.

Security telemetry must protect users without becoming a tool for monitoring them.

---

## 📥 Data Ingestion Principles

When a digital message enters the system:

- Raw message bodies are processed **in-memory only**
- Sensitive fields are **immediately transformed**
- Personally identifiable information (PII) is never stored persistently

The ingestion layer acts as a **privacy firewall** between raw data and system intelligence.

---

## 🔒 Sensitive Data Handling

| Data Type | Handling Method | Persistence |
|----------|-----------------|-------------|
| Email body content | Feature extraction only | Not stored |
| Email addresses | Tokenized (hashed) | Token only |
| Domains and URLs | Metadata analysis | Stored in normalized form |
| Message timestamps | Generalized time buckets | Stored |
| User identifiers | Pseudonymized tokens | Stored |

At no point does the system retain full message content or directly identifiable user information.

---

## 🧬 Tokenization & Pseudonymization

Sensitive identifiers are transformed using one-way hashing techniques.

### Purpose
- Allow correlation of repeated patterns
- Prevent reverse identification
- Preserve analytical value without exposing identity

This enables detection of campaign patterns without tracking individuals.

---

## 🗂️ Data Retention Policy

EXPLAIN-SEC enforces strict retention rules:

| Data Category | Retention Duration |
|---------------|-------------------|
| Raw ingestion data | Not stored |
| Tokenized event data | Short-term, rolling window |
| Aggregated statistics | Long-term (non-identifiable) |
| User feedback signals | Anonymized and aggregated |

Data that is not required for system improvement is automatically purged.

---

## 👥 Role-Based Access Control (RBAC)

System data visibility is role-dependent:

### Students
- See only explanations related to their own alerts
- No visibility into other users or system-wide trends

### Security Analysts
- View signal-level technical data
- No access to direct personal identifiers

### Administrators
- Access only aggregated institutional risk trends
- No per-user or individual event visibility

No role has unrestricted access to raw or identifiable data.

---

## 📊 Aggregated Analytics

Institutional dashboards display:

- Trend data (e.g., phishing volume increase)
- Risk posture metrics
- Signal distribution patterns

These metrics are **statistical summaries**, not individual behavior tracking.

---

## 🧱 Trust Boundaries

Privacy is enforced at multiple system boundaries:

| Boundary | Protection |
|----------|------------|
| Ingestion Boundary | Raw data transformed, not stored |
| Feature Boundary | Only derived features retained |
| Risk Boundary | Scoring occurs without identity context |
| Dashboard Boundary | Views filtered by role |
| Analytics Boundary | Aggregation prevents re-identification |

Each layer reduces exposure risk while preserving system utility.

---

## ⚠️ What EXPLAIN-SEC Explicitly Does NOT Do

- Store raw emails or attachments  
- Track user browsing behavior  
- Build individual behavioral risk profiles  
- Share data with third parties  
- Perform automated punitive actions  

These are intentional design exclusions to ensure ethical deployment.

---

## 🧩 Privacy vs Security Trade-Offs

EXPLAIN-SEC acknowledges that stricter privacy controls can reduce detection granularity.  
The system deliberately prioritizes:

- Trust over surveillance  
- Transparency over silent monitoring  
- Learning over punishment  

This trade-off reflects responsible security engineering in human-centered environments.

---

## 📌 Summary

EXPLAIN-SEC demonstrates that effective cybersecurity systems can be built with:

- Minimal data collection  
- Strong identity protections  
- Clear usage boundaries  
- Respect for user autonomy  

By embedding privacy into the architecture rather than adding it later, EXPLAIN-SEC ensures that **protection never becomes intrusion**.
