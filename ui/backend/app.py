from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import List

# Temporary in-memory storage (will improve later)
ALERT_STORE: List[dict] = []

app = FastAPI(
    title="Intrusion Detection System API",
    description="Backend API for IDS alerts and monitoring",
    version="1.0.0"
)

# Allow dashboard (frontend) to access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "IDS Backend API is running",
        "status": "OK"
    }


@app.get("/alerts")
def get_alerts():
    """
    Returns all detected IDS alerts
    """
    return {
        "count": len(ALERT_STORE),
        "alerts": ALERT_STORE
    }


@app.post("/alerts")
def add_alert(alert: dict):
    """
    Receives alerts from IDS core
    """
    ALERT_STORE.append(alert)
    return {
        "message": "Alert received",
        "total_alerts": len(ALERT_STORE)
    }


@app.delete("/alerts")
def clear_alerts():
    """
    Clears all alerts (useful for testing)
    """
    ALERT_STORE.clear()
    return {"message": "All alerts cleared"}
