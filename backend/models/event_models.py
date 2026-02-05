from pydantic import BaseModel

class EventInput(BaseModel):
    message_text: str
