from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
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
    ALERT_STORE.append(alert)

    # 🔥 PUSH ALERT TO WEBSOCKETS
    for ws in active_connections:
        await ws.send_json(alert)

    return {"message": "Alert received"}


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
