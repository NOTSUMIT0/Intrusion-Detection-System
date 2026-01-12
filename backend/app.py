from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import List

ALERT_STORE: List[dict] = []

app = FastAPI(
    title="Intrusion Detection System API",
    description="Backend API for IDS alerts and monitoring",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Later restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "OK", "message": "IDS Backend API running"}


@app.get("/alerts")
def get_alerts():
    return {
        "count": len(ALERT_STORE),
        "alerts": ALERT_STORE
    }


@app.post("/alerts")
def add_alert(alert: dict):
    ALERT_STORE.append(alert)
    return {"message": "Alert stored", "total": len(ALERT_STORE)}


@app.delete("/alerts")
def clear_alerts():
    ALERT_STORE.clear()
    return {"message": "All alerts cleared"}

