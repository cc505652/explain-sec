# Risk Scoring Logic  
## EXPLAIN-SEC Explainable Risk Assessment Framework

EXPLAIN-SEC does not produce binary “safe” or “malicious” labels.  
Instead, it evaluates digital events using a **transparent, weighted risk scoring model** designed for explainability, auditability, and human collaboration.

---

## 🎯 Purpose of Risk Scoring

The goal of the risk scoring engine is to:

- Provide **graduated threat assessment**
- Enable **human judgment** instead of rigid automation
- Support **clear, defensible explanations**
- Reduce alert fatigue by prioritizing meaningful threats

Risk is expressed as a score between **0 and 100**.

---

## 🧩 Core Design Principles

1. **Transparency Over Complexity**  
   The scoring model is interpretable and based on clearly defined signal weights.

2. **Risk, Not Certainty**  
   The system estimates likelihood of malicious intent, not definitive truth.

3. **Explainability by Construction**  
   Every score is decomposable into contributing signals.

4. **Configurable Policy Thresholds**  
   Institutions can adjust sensitivity without modifying core logic.

---

## 🧠 Scoring Model Overview
Risk Score = Σ (Signal Weight × Signal Confidence)


Where:

- **Signal Weight** reflects the severity and reliability of the signal
- **Signal Confidence** reflects how strongly the signal is present (0–1 scale)

The score is then normalized to a 0–100 scale.

---

## 📊 Example Signal Weight Distribution

| Signal Category | Example Signals | Typical Weight Range |
|-----------------|-----------------|----------------------|
| Identity Authenticity | Domain mismatch, SPF failure | 10–25 |
| Infrastructure | Redirect chains, domain age | 10–20 |
| Social Engineering | Urgency language, impersonation | 8–18 |
| Behavioral | Bulk sending, time anomaly | 5–15 |
| Structural | Header mismatch, obfuscated links | 5–15 |

Higher weights are assigned to signals strongly correlated with confirmed phishing behavior.

---

## 🔍 Signal Confidence Scoring

Signals are not always binary. Each signal is evaluated on a confidence scale:

| Confidence Level | Meaning |
|------------------|---------|
| 0.0 | Signal not present |
| 0.3 | Weak indication |
| 0.6 | Moderate indication |
| 1.0 | Strong indication |

Example:  
Urgency language appearing multiple times → Confidence = 0.8  
Single mild urgency phrase → Confidence = 0.3

---

## ⚖️ Risk Bands

The final normalized risk score is mapped into decision bands:

| Risk Score | Risk Level | System Response |
|------------|------------|----------------|
| 0–30 | Low | No alert, passive monitoring |
| 31–60 | Medium | User caution with explanation |
| 61–80 | High | Strong warning with guidance |
| 81–100 | Critical | Immediate alert, recommend verification |

These bands are configurable in the system configuration.

---

## 🧠 Contribution Breakdown

Every risk score includes a breakdown of the top contributing signals:

Example Output:
Risk Score: 78 (High)

Top Contributors:

Newly registered sender domain (22%)

Urgency language pattern (18%)

Suspicious redirect chain (15%)


This ensures **no alert exists without reasoning**.

---

## 🔄 Feedback-Adjusted Confidence

User feedback influences the confidence weighting over time:

| Feedback Type | Effect |
|---------------|--------|
| User confirms phishing | Increase weight of contributing signals |
| User marks safe | Slightly reduce signal confidence |
| Analyst override | Recalibrate risk mapping |

This creates a **learning system** without storing personal history.

---

## ⚠️ False Positive Handling

The system is intentionally conservative in low-confidence scenarios.

Mitigation strategies include:
- Medium-risk alerts instead of hard blocking
- Clear explanation to allow user judgment
- Confidence adjustment through feedback

False positives are treated as **learning opportunities**, not system failures.

---

## 🔐 Privacy Safeguards in Scoring

The risk engine operates on:
- Tokenized identifiers
- Derived metadata features
- Pattern-based indicators

No raw content or direct identifiers are required for scoring.

---

## 📈 Extensibility

New signals can be added by:

1. Defining a weight
2. Specifying a confidence calculation method
3. Mapping it to an explanation template

This allows adaptation to emerging threats while maintaining transparency.

---

## 📌 Summary

EXPLAIN-SEC’s risk scoring framework:

- Replaces opaque classification with **interpretable risk estimation**
- Supports human decision-making rather than automation-only security
- Balances detection accuracy with trust and explainability
- Enables continuous improvement through privacy-safe feedback

The result is a system where **every security decision can be understood, justified, and refined**.

The total risk score is calculated using a weighted additive model:

