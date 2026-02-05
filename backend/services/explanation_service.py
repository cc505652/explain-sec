EXPLANATION_MAP = {
    "suspicious_link": "The message contains a link which could lead to a fake or malicious website.",
    "urgency_language": "It uses urgent language to pressure you into acting quickly.",
    "fear_tactic": "It creates fear (like account suspension) to manipulate you.",
    "credential_harvest": "It asks for login or password information, which is a phishing tactic.",
    "authority_impersonation": "It pretends to be from an authority (bank, admin, IT team).",
    "financial_bait": "It promises money or rewards to lure you.",
    "attachment_lure": "It references an attachment that may contain malware.",
    "account_problem": "It claims there is an issue with your account to make you react emotionally.",
}


def generate_explanation(signals: list, risk_level: str):
    if not signals:
        return "No strong phishing indicators were detected."

    reasons = [EXPLANATION_MAP.get(sig, "Suspicious behavior detected.") for sig in signals[:3]]

    explanation = f"Risk Level: {risk_level}. "
    explanation += " ".join(reasons)

    return explanation
