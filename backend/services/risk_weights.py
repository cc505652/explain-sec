SIGNAL_WEIGHTS = {
    "domain_age_new": {"weight": 20, "type": "boolean"},
    "domain_mismatch": {"weight": 15, "type": "boolean"},
    "spf_fail": {"weight": 15, "type": "boolean"},
    "urgent_language": {"weight": 12, "type": "ratio"},
    "threat_language": {"weight": 10, "type": "ratio"},
    "redirect_chain": {"weight": 10, "type": "count"},
    "ip_based_url": {"weight": 8, "type": "boolean"},
    "attachment_risky": {"weight": 10, "type": "boolean"},
    "first_time_sender": {"weight": 8, "type": "boolean"}
}

RISK_THRESHOLDS = {
    "medium": 30,
    "high": 60,
    "critical": 80
}
