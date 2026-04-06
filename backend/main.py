from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router as api_router
from backend.state import ids_state
from backend.utils import utc_now


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="Intrusion Activity Detection & Attack Trace System",
    description="Real-time IDS backend with log parsing, detection, correlation, WebSockets, and PDF reporting.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = Path("frontend")
app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")
app.include_router(api_router)


@app.get("/")
async def serve_dashboard() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")


@app.get("/status")
async def status() -> dict[str, Any]:
    snapshot = ids_state.snapshot()
    return {
        "timestamp": utc_now(),
        "monitoring_active": snapshot["monitoring_active"],
        "monitored_files": snapshot["monitored_files"],
        "source_mode": snapshot["source_mode"],
        "scan_mode": snapshot["scan_mode"],
        "last_report_path": snapshot["last_report_path"],
    }


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    await ids_state.manager.connect(websocket)
    try:
        await websocket.send_json({"type": "snapshot", "data": ids_state.snapshot()})
        while True:
            message = await websocket.receive_text()
            await websocket.send_json(
                {
                    "type": "heartbeat",
                    "data": {"message": message, "timestamp": utc_now()},
                }
            )
    except WebSocketDisconnect:
        ids_state.manager.disconnect(websocket)
    except Exception:
        ids_state.manager.disconnect(websocket)
