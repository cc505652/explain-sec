# EXPLAIN-SEC System Architecture

EXPLAIN-SEC is designed as a modular, privacy-preserving, explainable security intelligence platform.  
Its architecture prioritizes **clarity, separation of concerns, and trust boundaries** over monolithic design.

The system is built around the principle that **security decisions must be explainable, risk-based, and human-aware**.

---

## 🧱 High-Level Architecture

EXPLAIN-SEC consists of six primary layers:

1. **Ingestion & Signal Extraction Layer**
2. **Risk Scoring Engine**
3. **Explainability Engine**
4. **Privacy Protection Layer**
5. **Human-in-the-Loop Feedback System**
6. **Role-Based Visualization Dashboard**

Each layer is independently testable and designed with strict data boundaries.

---

## 1️⃣ Ingestion & Signal Extraction Layer

**Purpose:** Convert raw digital events into structured, privacy-safe security signals.

### Inputs
- Email metadata (headers, sender domain)
- URL and link metadata
- Message structure and language patterns
- Behavioral context (time, frequency, anomalies)

### Responsibilities
- Extract explainable security signals
- Avoid long-term storage of raw message content
- Normalize data into structured features

### Outputs
- Tokenized, structured feature set
- No persistent raw PII

This layer transforms unstructured data into **auditable signals**, not black-box embeddings.

---

## 2️⃣ Risk Scoring Engine

**Purpose:** Convert signals into a contextual risk score.

Instead of binary classification, EXPLAIN-SEC uses a **weighted, explainable scoring model**.

### Core Characteristics
- Risk score range: **0–100**
- Weighted signal contributions
- Confidence bands: Low / Medium / High
- Thresholds configurable via policy

### Example Output
Risk Score: 78 (High)
Top Contributors:

Newly registered sender domain

Urgent account-related language

Suspicious redirect chain


The scoring engine is intentionally transparent and rule-auditable.

---

## 3️⃣ Explainability Engine

**Purpose:** Translate risk signals into human-understandable explanations.

Different stakeholders require different explanation styles.

### Explanation Types

| Role | Explanation Style |
|------|------------------|
| Student | Plain language, actionable guidance |
| Security Analyst | Signal weights and contributing factors |
| Administrator | Aggregated trends and system posture |

The system never presents unexplained security decisions.

---

## 4️⃣ Privacy Protection Layer

**Purpose:** Enforce privacy-by-design at every stage of the system.

### Privacy Controls

- Immediate tokenization of sensitive fields
- No persistent storage of raw email bodies
- Role-based data visibility
- Aggregated analytics for institutional insights
- Data retention limits enforced by policy

### Privacy Philosophy
Security telemetry must **protect users without monitoring them**.

This layer ensures detection does not become surveillance.

---

## 5️⃣ Human-in-the-Loop Feedback System

**Purpose:** Incorporate user input to improve system understanding and promote security awareness.

### Workflow
1. Risk alert generated
2. User receives explanation
3. User action recorded (report, ignore, confirm)
4. Feedback influences system confidence weighting

This creates a **learning loop** that improves both:
- System detection reliability
- User security awareness

---

## 6️⃣ Role-Based Visualization Dashboard

**Purpose:** Provide contextual system visibility without exposing private user data.

### Views

**Student Dashboard**
- Personal risk explanations
- Recommended actions
- Security hygiene guidance

**Analyst Dashboard**
- Signal-level explanations
- Event breakdowns
- Risk trend monitoring

**Administrator Dashboard**
- Aggregate threat posture
- Trend analysis
- No individual tracking

Each dashboard respects strict **role-based access controls**.

---

## 🔐 Trust Boundaries

EXPLAIN-SEC enforces clear separation between system layers:

| Boundary | Purpose |
|----------|---------|
| Ingestion Boundary | Raw data transformed and tokenized |
| Signal Boundary | Structured features only |
| Risk Boundary | Scoring without PII context |
| Explanation Boundary | Human-readable summaries |
| Analytics Boundary | Aggregated institutional metrics |

No single component has unrestricted access to raw and identifiable data.

---

## 🔄 End-to-End Flow

1. A digital message enters the system
2. Signals are extracted and sensitive data is tokenized
3. Risk score is calculated using explainable weighting
4. Explanation is generated for the appropriate audience
5. User interaction provides feedback
6. Aggregated insights update institutional threat awareness

At every stage, **privacy is preserved and reasoning remains transparent**.

---

## ⚙️ Modularity & Extensibility

The system is designed to evolve safely:

- New signal modules can be added without redesigning the system
- Risk weights are configurable
- Explanation templates are role-specific and editable
- Privacy rules are policy-driven

This allows adaptation to new threat patterns while maintaining trust.

---

## 🧠 Architectural Philosophy

EXPLAIN-SEC does not aim to replace human judgment.  
It augments decision-making with:

- Context  
- Transparency  
- Privacy guarantees  

The result is a system that is not only technically effective, but also **deployable in environments where trust is essential**.

---

## 📌 Summary

EXPLAIN-SEC demonstrates that modern security systems can be:

- **Explainable instead of opaque**
- **Privacy-preserving instead of intrusive**
- **Human-aware instead of purely automated**

This architecture balances security effectiveness with ethical responsibility — a necessary foundation for real-world deployment.
