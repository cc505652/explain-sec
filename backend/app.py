from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes.analyze import router as analyze_router

app = FastAPI(title="EXPLAIN-SEC Threat Engine")

# Allow frontend (React) to call backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change later for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ DO NOT ADD EXTRA PREFIX HERE
app.include_router(analyze_router)


@app.get("/")
def root():
    return {
        "system": "EXPLAIN-SEC",
        "status": "running",
        "engine": "AI Threat Detection Core"
    }

