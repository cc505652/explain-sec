from fastapi import APIRouter
from backend.services.dashboard_service import (
    generate_risk_trend,
    get_top_signals,
    get_risk_distribution,
    get_recent_campaign_patterns
)

router = APIRouter()


@router.get("/overview")
def dashboard_overview():
    return {
        "risk_trend": generate_risk_trend(),
        "risk_distribution": get_risk_distribution(),
        "top_signals": get_top_signals(),
        "campaign_patterns": get_recent_campaign_patterns()
    }
