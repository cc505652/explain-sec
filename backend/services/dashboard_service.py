from datetime import datetime, timedelta
import random


def generate_risk_trend():
    """
    Simulates institutional phishing trend over time.
    No user-level data — only aggregate posture.
    """
    base = 50
    trend = []
    for i in range(7):
        variation = random.randint(-5, 10)
        trend.append({
            "date": (datetime.now() - timedelta(days=6-i)).strftime("%Y-%m-%d"),
            "risk_index": max(10, min(100, base + variation))
        })
    return trend


def get_top_signals():
    """
    Simulated top contributing signals across the institution.
    """
    return [
        {"signal": "domain_age_new", "frequency": 32},
        {"signal": "urgent_language", "frequency": 27},
        {"signal": "redirect_chain", "frequency": 19},
        {"signal": "domain_mismatch", "frequency": 15},
        {"signal": "attachment_risky", "frequency": 11}
    ]


def get_risk_distribution():
    """
    Shows percentage distribution of alerts by severity.
    """
    return {
        "low": 42,
        "medium": 33,
        "high": 18,
        "critical": 7
    }


def get_recent_campaign_patterns():
    """
    Example campaign-style phishing patterns detected.
    """
    return [
        {
            "pattern": "Exam-related urgency phishing",
            "common_signal": "urgent_language",
            "estimated_volume": 14
        },
        {
            "pattern": "Fake IT support credential harvesting",
            "common_signal": "domain_mismatch",
            "estimated_volume": 9
        }
    ]
