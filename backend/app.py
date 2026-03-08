from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

app = FastAPI(
    title="Intrusion Detection System API",
    description="Backend API for IDS alerts and monitoring",
    version="1.0.0"
)

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- STORAGE ----------------
ALERT_STORE: List[dict] = []
active_connections: List[WebSocket] = []


# ---------------- MODELS ----------------
class StatusUpdate(BaseModel):
    status: str   # "investigating" | "resolved"


# ---------------- REST API ----------------
@app.get("/")
def root():
    return {"status": "OK"}

@app.get("/alerts")
def get_alerts():
    return {
        "count": len(ALERT_STORE),
        "alerts": ALERT_STORE
    }

@app.post("/alerts")
async def add_alert(alert: dict):
    alert.setdefault("status", "new")
    ALERT_STORE.append(alert)

    # PUSH ALERT TO WEBSOCKETS---------------
    for ws in active_connections:
        await ws.send_json(alert)

    return {"message": "Alert received"}


# ---------------- STATUS MANAGEMENT ----------------
@app.patch("/alerts/{timestamp}/status")
def update_alert_status(timestamp: str, body: StatusUpdate):
    """Update the lifecycle status of an alert identified by its timestamp."""
    for alert in ALERT_STORE:
        if alert.get("timestamp") == timestamp:
            alert["status"] = body.status
            return {"message": "Status updated", "alert": alert}
    return {"message": "Alert not found"}


@app.get("/alerts/investigating")
def get_investigating_alerts():
    """Return all alerts currently under investigation."""
    investigating = [a for a in ALERT_STORE if a.get("status") == "investigating"]
    return {"count": len(investigating), "alerts": investigating}


@app.get("/alerts/resolved")
def get_resolved_alerts():
    """Return all resolved alerts."""
    resolved = [a for a in ALERT_STORE if a.get("status") == "resolved"]
    return {"count": len(resolved), "alerts": resolved}


# ---------------- WEBSOCKET ----------------
@app.websocket("/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        active_connections.remove(websocket)
