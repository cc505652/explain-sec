import hashlib
from typing import Dict, Any


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def sanitize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = {
        "signals": event.get("signals", {}),
        "metadata": {}
    }

    metadata = event.get("metadata", {})

    if "sender_email" in metadata and isinstance(metadata["sender_email"], str):
        sanitized["metadata"]["sender_token"] = hash_value(metadata["sender_email"])

    if "recipient_email" in metadata and isinstance(metadata["recipient_email"], str):
        sanitized["metadata"]["recipient_token"] = hash_value(metadata["recipient_email"])

    # Safe timestamp handling
    timestamp = metadata.get("timestamp")
    if isinstance(timestamp, str) and "T" in timestamp:
        try:
            hour = int(timestamp.split("T")[1][:2])
            if 0 <= hour < 6:
                bucket = "late_night"
            elif 6 <= hour < 12:
                bucket = "morning"
            elif 12 <= hour < 18:
                bucket = "afternoon"
            else:
                bucket = "evening"
            sanitized["metadata"]["time_bucket"] = bucket
        except:
            sanitized["metadata"]["time_bucket"] = "unknown"

    return sanitized
