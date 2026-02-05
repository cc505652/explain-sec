from pydantic import BaseModel
from typing import List, Optional

class EventInput(BaseModel):
    sender_domain: str
    subject: Optional[str]
    urls: List[str]
    content_features: dict
    metadata: dict
