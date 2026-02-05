from typing import Dict, Any, List
import re
from urllib.parse import urlparse


SUSPICIOUS_ATTACHMENT_TYPES = [".exe", ".js", ".scr", ".bat", ".cmd", ".docm", ".xlsm"]
URGENCY_KEYWORDS = ["urgent", "immediately", "action required", "asap", "now"]
THREAT_KEYWORDS = ["suspended", "terminated", "blocked", "penalty", "legal action"]


def is_domain_new(domain_age_days: int) -> bool:
    return domain_age_days < 30


def has_domain_mismatch(display_name: str, sender_domain: str) -> bool:
    return sender_domain.lower() not in display_name.lower()


def contains_keywords(text: str, keywords: List[str]) -> float:
    """
    Returns ratio of suspicious keywords present in text.
    """
    text_lower = text.lower()
    matches = sum(1 for kw in keywords if kw in text_lower)
    return min(matches / len(keywords), 1.0)


def count_redirects(url_chain_length: int) -> int:
    return url_chain_length


def is_ip_based_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname or ""))
    except:
        return False


def has_risky_attachment(attachments: List[str]) -> bool:
    for file in attachments:
        for ext in SUSPICIOUS_ATTACHMENT_TYPES:
            if file.lower().endswith(ext):
                return True
    return False


def is_first_time_sender(prior_contact_count: int) -> bool:
    return prior_contact_count == 0


def build_signals(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts extracted event features into explainable security signals.
    This function does NOT store raw content — only derived indicators.
    """

    signals = {}

    # Identity signals
    signals["domain_age_new"] = is_domain_new(event.get("domain_age_days", 999))
    signals["domain_mismatch"] = has_domain_mismatch(
        event.get("display_name", ""),
        event.get("sender_domain", "")
    )
    signals["spf_fail"] = event.get("spf_failed", False)

    # Content/social engineering signals
    subject = event.get("subject", "")
    body_preview = event.get("body_preview", "")  # short snippet, not full body

    combined_text = f"{subject} {body_preview}"
    signals["urgent_language"] = contains_keywords(combined_text, URGENCY_KEYWORDS)
    signals["threat_language"] = contains_keywords(combined_text, THREAT_KEYWORDS)

    # Infrastructure signals
    signals["redirect_chain"] = count_redirects(event.get("redirect_chain_length", 0))

    urls = event.get("urls", [])
    signals["ip_based_url"] = any(is_ip_based_url(url) for url in urls)

    # Attachment signals
    signals["attachment_risky"] = has_risky_attachment(event.get("attachments", []))

    # Behavioral signals
    signals["first_time_sender"] = is_first_time_sender(
        event.get("prior_contact_count", 0)
    )

    return signals
