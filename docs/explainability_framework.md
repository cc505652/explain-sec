# Explainability Framework  
## Human-Centered Security Reasoning in EXPLAIN-SEC

EXPLAIN-SEC is built on the belief that a security decision is incomplete unless it can be clearly explained to the person affected by it.

This framework defines how technical risk signals are translated into **understandable, actionable, and role-appropriate explanations**.

---

## 🎯 Goals of Explainability

The explainability system is designed to:

- Make security decisions **transparent**
- Enable users to make **informed judgments**
- Reduce confusion and alert fatigue
- Build trust without exposing sensitive data
- Support analysts with interpretable technical reasoning

Explainability is not an afterthought — it is a **core system output**.

---

## 🧩 Three-Tier Explanation Model

EXPLAIN-SEC generates different explanations depending on the audience.

| Audience | Purpose | Style |
|----------|---------|-------|
| Student | Immediate understanding and safe action | Plain, non-technical language |
| Security Analyst | Technical verification and triage | Signal-weighted reasoning |
| Administrator | Institutional awareness and posture | Aggregated trends and summaries |

Each explanation is generated from the same signal data but translated appropriately.

---

## 1️⃣ Student-Focused Explanations

### Objectives
- Clearly explain why the message is risky
- Provide actionable next steps
- Avoid technical jargon
- Avoid fear-based language

### Structure
1. Risk Level (Low / Medium / High / Critical)
2. Plain-language reason
3. What this means
4. Recommended action

### Example

> **Risk Level: High**  
> This message appears suspicious because it came from a newly created website and asks you to act urgently.  
> Attackers often use these tactics to trick people into sharing login details.  
> **Recommended Action:** Do not click any links. Verify with official channels.

---

## 2️⃣ Analyst-Focused Explanations

### Objectives
- Provide technical transparency
- Show which signals contributed most
- Enable validation or override decisions

### Structure
1. Risk score and confidence
2. Top contributing signals with weights
3. Signal confidence levels
4. Supporting metadata (privacy-safe)

### Example
Risk Score: 78 (High)

Top Signals:

Domain Age < 30 days (Weight 20, Confidence 0.9)

Urgency Language Pattern (Weight 15, Confidence 0.8)

Redirect Chain Length > 2 (Weight 12, Confidence 0.7)


Analysts can trace exactly how the score was derived.

---

## 3️⃣ Administrator-Focused Explanations

### Objectives
- Provide macro-level awareness
- Show trends without exposing individuals
- Support institutional decision-making

### Structure
1. Trend summary
2. Signal distribution patterns
3. Risk posture over time
4. Notable threat campaigns

### Example

> Phishing attempts increased by 18% during the exam period.  
> The most common signals involved newly registered domains and impersonation of academic staff.

No individual user data is displayed.

---

## 🔍 Signal-to-Explanation Mapping

Each detection signal has a predefined explanation template.

| Signal | Student Explanation | Analyst Explanation |
|--------|--------------------|--------------------|
| Domain Age < 30 days | “The message came from a recently created website.” | Domain registration age indicates potential phishing infrastructure |
| Urgency Language | “The message tries to rush you into acting quickly.” | High urgency phrase density detected |
| Redirect Chain | “The link goes through multiple websites before its final destination.” | Redirect chain length exceeds normal patterns |

This ensures explanations are consistent and traceable.

---

## 🧠 Explanation Generation Process

1. Risk scoring engine identifies top contributing signals
2. Signals are ranked by weighted impact
3. Explanation templates are selected
4. Language is adapted based on user role
5. Sensitive details are excluded or generalized

This creates explanations that are **accurate without being intrusive**.

---

## ⚖️ Explainability vs Privacy

The system balances clarity with privacy by:

- Avoiding exposure of full message content
- Using generalized phrasing instead of quoting messages
- Describing patterns rather than specific personal details

Example:

Instead of:
> “Your email from john_doe123@gmail.com…”

The system says:
> “This message came from an unfamiliar sender.”

---

## 🔄 Explainability in the Feedback Loop

When users provide feedback:
- The system can explain how that feedback influenced confidence
- Analysts can see when signals were reweighted

This keeps the system **transparent even when it evolves**.

---

## ⚠️ Handling Uncertainty

When confidence is low, explanations explicitly reflect uncertainty.

Example:

> “Some elements of this message look unusual, but there is not enough evidence to confirm it is malicious. Please review carefully.”

This prevents false certainty and builds user trust.

---

## 📌 Summary

The EXPLAIN-SEC Explainability Framework ensures that:

- Every risk decision has a clear reason
- Different users receive explanations they can understand
- Security transparency does not compromise privacy
- Trust is built through clarity, not authority

Explainability transforms the system from a silent detector into a **collaborative security partner**.



