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
    return {
        "count": len(ALERT_STORE),
        "alerts": ALERT_STORE
    }


@app.post("/alerts")
def add_alert(alert: dict):
    ALERT_STORE.append(alert)
    return {
        "message": "Alert received",
        "total_alerts": len(ALERT_STORE)
    }


@app.delete("/alerts")
def clear_alerts():
    ALERT_STORE.clear()
    return {"message": "All alerts cleared"}
