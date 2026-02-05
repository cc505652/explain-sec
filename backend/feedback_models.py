from pydantic import BaseModel

class FeedbackInput(BaseModel):
    event_id: str
    user_action: str  # "phishing", "safe", "unsure"
