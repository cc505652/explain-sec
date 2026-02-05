# -----------------------------
# 🎯 Base Signal Weights
# -----------------------------
SIGNAL_WEIGHTS = {
    "suspicious_link": 35,
    "urgency_language": 18,
    "fear_tactic": 22,
    "credential_harvest": 30,
    "authority_impersonation": 18,
    "financial_bait": 32,      # 🔥 increased
    "attachment_lure": 20,
    "account_problem": 22,
}


# -----------------------------
# 🧠 Risk Score Calculator
# -----------------------------
def calculate_risk_score(signals: list):
    score = 0

    # Base signal contribution
    for signal in signals:
        score += SIGNAL_WEIGHTS.get(signal, 5)

    # -----------------------------
    # 🚨 Pattern-Based Escalation
    # -----------------------------
    # Classic phishing combo
    if "suspicious_link" in signals and "urgency_language" in signals:
        score += 15

    # Fake login portal
    if "suspicious_link" in signals and "credential_harvest" in signals:
        score += 20

    # Authority fear manipulation
    if "authority_impersonation" in signals and "fear_tactic" in signals:
        score += 15

    # Multiple tactics used = higher confidence attack
    if len(signals) >= 3:
        score += 10
    # Financial scam pattern
    if "financial_bait" in signals and "urgency_language" in signals:
    	score += 20

    # Prize + link = dangerous lure
    if "financial_bait" in signals and "suspicious_link" in signals:
    	score += 20

    # Pure social engineering attempt (no tech indicator but persuasive scam)
    if "financial_bait" in signals and len(signals) == 1:
    	score += 10

    # -----------------------------
    # 🟢 False Positive Dampener
    # -----------------------------
    if score < 25 and len(signals) <= 1 and "financial_bait" not in signals:
    	score = max(score - 10, 0)

    return min(score, 100)  # Cap risk at 100


# -----------------------------
# 🚦 Risk Level Mapping
# -----------------------------
def get_risk_level(score: int):
    if score >= 85:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 35:
        return "Medium"
    else:
        return "Low"
