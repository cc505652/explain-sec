from typing import Dict, Any
from detection_engine.feature_builder import build_signals


def run_signal_pipeline(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main signal processing pipeline.

    Converts raw extracted email/URL metadata into
    structured security signals ready for risk scoring.

    IMPORTANT:
    - No raw message bodies should leave this stage
    - Only derived signals and minimal metadata are passed forward
    """

    # Step 1: Build explainable security signals
    signals = build_signals(raw_event)

    # Step 2: Construct privacy-aware event payload
    processed_event = {
        "signals": signals,
        "metadata": {
            # Minimal metadata only — no PII
            "source": raw_event.get("source", "email"),
            "ingestion_time": raw_event.get("ingestion_time", "unknown"),
        }
    }

    return processed_event


if __name__ == "__main__":
    # Example test event (safe for demo — no real data)
    demo_event = {
        "source": "email",
        "ingestion_time": "2026-02-04T10:15:00",
        "domain_age_days": 5,
        "display_name": "University IT Support",
        "sender_domain": "university-it-helpdesk.com",
        "spf_failed": True,
        "subject": "URGENT: Account Suspension Notice",
        "body_preview": "Your account will be suspended immediately unless you verify now.",
        "redirect_chain_length": 3,
        "urls": ["http://192.168.0.5/login"],
        "attachments": ["update.docm"],
        "prior_contact_count": 0
    }

    result = run_signal_pipeline(demo_event)
    print("Generated Signals:")
    print(result)
