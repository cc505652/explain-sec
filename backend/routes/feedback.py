from fastapi import APIRouter
from backend.models.feedback_models import FeedbackInput
from backend.services.scoring_service import adjust_confidence

router = APIRouter()

@router.post("/")
def submit_feedback(feedback: FeedbackInput):
    adjust_confidence(feedback)
    return {"status": "feedback recorded"}
