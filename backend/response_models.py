from pydantic import BaseModel
from typing import List

class RiskResponse(BaseModel):
    risk_score: int
    risk_level: str
    top_signals: List[str]
    explanation: str
