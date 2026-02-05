from fastapi import APIRouter
from backend.models.event_models import EventInput
from backend.services.scoring_service import calculate_risk_score, get_risk_level
from backend.services.explanation_service import generate_explanation

router = APIRouter(prefix="/analyze", tags=["Threat Analysis"])


def extract_signals(text: str):
    text_lower = text.lower()
    signals = []

    if "http://" in text_lower or "https://" in text_lower or "bit.ly" in text_lower:
        signals.append("suspicious_link")

    if any(w in text_lower for w in ["urgent", "immediately", "act now", "asap"]):
        signals.append("urgency_language")

    if any(w in text_lower for w in ["locked", "suspended", "terminated", "security breach"]):
        signals.append("fear_tactic")

    if any(w in text_lower for w in ["login", "verify password", "confirm account", "reset password"]):
        signals.append("credential_harvest")

    if any(w in text_lower for w in ["bank", "support team", "it department", "admin", "security team"]):
        signals.append("authority_impersonation")

    if any(w in text_lower for w in ["refund", "prize", "lottery", "reward", "cashback"]):
        signals.append("financial_bait")

    if any(w in text_lower for w in ["invoice", "attached file", "document attached", "pdf attached"]):
        signals.append("attachment_lure")

    if any(w in text_lower for w in ["account issue", "unauthorized login", "unusual activity"]):
        signals.append("account_problem")

    return signals


@router.post("/")
def analyze_event(event: EventInput):
    signals = extract_signals(event.message_text)
    risk_score = calculate_risk_score(signals)
    risk_level = get_risk_level(risk_score)
    explanation = generate_explanation(signals, risk_level)

    confidence = min(len(signals) * 25, 100)

    return {
    "risk_score": risk_score,
    "risk_level": risk_level,
    "confidence": confidence,
    "top_signals": signals[:3],
    "explanation": explanation
}

