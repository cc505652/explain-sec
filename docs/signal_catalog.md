# Signal Catalog  
## EXPLAIN-SEC Detection Intelligence Framework

EXPLAIN-SEC does not rely on opaque model embeddings.  
Instead, it uses **explicit, explainable security signals** derived from message metadata, infrastructure characteristics, and contextual patterns.

Each signal is:
- Interpretable
- Independently auditable
- Privacy-aware
- Mapped to real-world phishing behaviors

---

# 🧩 Signal Categories

1. Identity & Sender Authenticity Signals  
2. Infrastructure & URL Signals  
3. Content & Social Engineering Signals  
4. Behavioral & Contextual Signals  
5. Structural & Technical Anomalies  

Each signal contributes a weighted value to the overall risk score.

---

## 1️⃣ Identity & Sender Authenticity Signals

These signals assess whether the sender’s identity appears legitimate.

| Signal Name | Description | Why It Matters |
|-------------|-------------|----------------|
| **Domain Age** | Age of sender domain based on registration metadata | Phishing domains are often newly registered |
| **Domain Mismatch** | Sender display name does not match sending domain | Common impersonation tactic |
| **Lookalike Domain** | Domain visually resembles trusted institution | Typosquatting and spoofing |
| **Free Email Provider Use** | Institutional message sent from public provider | Legitimate institutions rarely use free domains for official notices |
| **SPF/DKIM/DMARC Failure** | Authentication checks fail or are misaligned | Indicates spoofed or forged email source |

---

## 2️⃣ Infrastructure & URL Signals

These signals evaluate embedded links and redirection patterns.

| Signal Name | Description | Why It Matters |
|-------------|-------------|----------------|
| **Newly Registered URL Domain** | Link domain is recently created | Strong phishing indicator |
| **URL Redirect Chain Length** | Number of redirects before final destination | Attackers use redirection to evade detection |
| **High Entropy URL Path** | Random-looking strings in URL path | Often used in credential harvesting pages |
| **IP-based URL** | Link uses IP address instead of domain | Common in malicious hosting |
| **HTTPS Certificate Anomaly** | Self-signed or mismatched certificates | Indicates untrusted hosting |

---

## 3️⃣ Content & Social Engineering Signals

These signals analyze language patterns without storing raw content.

| Signal Name | Description | Why It Matters |
|-------------|-------------|----------------|
| **Urgency Language Score** | Presence of time-pressure phrases | Phishing often relies on urgency |
| **Threat Language Score** | Mentions of penalties, suspension, or loss | Emotional manipulation tactic |
| **Credential Request Pattern** | Requests for login, password, or verification | Core phishing objective |
| **Financial Request Indicator** | Mentions of payments, refunds, invoices | Common in academic scams |
| **Impersonation Language Pattern** | Claims to be admin, IT support, or faculty | Authority-based social engineering |

---

## 4️⃣ Behavioral & Contextual Signals

These signals consider timing and communication patterns.

| Signal Name | Description | Why It Matters |
|-------------|-------------|----------------|
| **Unusual Sending Time** | Message sent outside typical institutional hours | Automation or foreign campaign indicator |
| **Bulk Distribution Pattern** | Same message pattern across multiple recipients | Campaign-style phishing |
| **Event Correlation** | Message aligns with exams, admissions, deadlines | Attackers exploit academic stress periods |
| **First-Time Sender** | No prior history of communication | Suspicious when claiming authority |
| **Sender Frequency Spike** | Sudden burst of messages from same source | Automated phishing activity |

---

## 5️⃣ Structural & Technical Anomalies

These signals identify inconsistencies in technical structure.

| Signal Name | Description | Why It Matters |
|-------------|-------------|----------------|
| **Header Inconsistency** | Mismatch in routing headers | Spoofing indicator |
| **Reply-To Mismatch** | Reply-to address differs from sender domain | Common phishing redirection |
| **Attachment Type Risk** | Suspicious file types (e.g., macro-enabled docs) | Malware delivery vector |
| **Obfuscated Links** | URL text differs from actual destination | Deception technique |
| **HTML Form Presence** | Embedded login or input forms | Credential harvesting attempt |

---

# ⚖️ Signal Weighting Philosophy

Each signal contributes a weighted value to the overall risk score based on:

- Historical phishing prevalence
- Reliability as an indicator
- Likelihood of false positives
- Privacy sensitivity

Signals are combined using a **transparent, additive scoring model**, not a hidden ML black box.

---

# 🔍 Explainability Mapping

Every signal is directly mapped to a human-readable explanation.

Example:

| Signal Triggered | Explanation for User |
|------------------|---------------------|
| Domain Age < 30 days | “This message came from a newly created website, which is common in phishing attacks.” |
| Urgency Language High | “The message creates time pressure, a tactic often used to rush decisions.” |

This mapping ensures every risk factor can be communicated clearly.

---

# 🔐 Privacy Considerations

Signals are derived using:
- Metadata and structural analysis
- Pattern detection without storing raw content
- Tokenized identifiers

The system avoids storing personal communications while still identifying threat patterns.

---

# 📌 Summary

The EXPLAIN-SEC signal framework is designed to:

- Reflect real-world phishing techniques  
- Enable transparent risk scoring  
- Support human-readable explanations  
- Preserve user privacy  

By modeling **why** an attack is suspicious rather than just predicting that it is, EXPLAIN-SEC creates a detection system that users and institutions can trust.
