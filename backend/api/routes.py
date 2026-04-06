from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.realtime.monitor import realtime_monitor
from backend.reports.pdf_report import report_generator
from backend.state import ids_state
from backend.utils import utc_now


class MonitoringRequest(BaseModel):
    file_paths: list[str] = Field(default_factory=list)
    mode: str = "auto"
    scan_mode: str = "live"


router = APIRouter()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "timestamp": utc_now()}


@router.get("/logs")
async def get_logs() -> dict[str, Any]:
    return {"count": len(ids_state.logs), "items": [item.to_dict() for item in ids_state.logs]}


@router.get("/alerts")
async def get_alerts() -> dict[str, Any]:
    return {"count": len(ids_state.alerts), "items": [item.to_dict() for item in ids_state.alerts]}


@router.get("/timeline")
async def get_timeline() -> dict[str, Any]:
    return {"count": len(ids_state.timeline), "items": [item.to_dict() for item in ids_state.timeline]}


@router.get("/attack-chains")
async def get_attack_chains() -> dict[str, Any]:
    return {
        "count": len(ids_state.attack_chains),
        "items": [item.to_dict() for item in ids_state.attack_chains],
    }


@router.post("/monitoring/start")
async def start_monitoring(payload: MonitoringRequest | None = None) -> dict[str, Any]:
    file_paths = payload.file_paths if payload else []
    mode = payload.mode if payload else "auto"
    scan_mode = payload.scan_mode if payload else "live"
    result = await realtime_monitor.start(file_paths=file_paths or None, mode=mode, scan_mode=scan_mode)
    return {"timestamp": utc_now(), **result, "files": ids_state.monitored_files}


@router.post("/monitoring/stop")
async def stop_monitoring() -> dict[str, Any]:
    result = await realtime_monitor.stop()
    return {"timestamp": utc_now(), **result, "report_path": ids_state.last_report_path}


@router.get("/report/download")
async def download_report() -> FileResponse:
    report_path = ids_state.last_report_path
    if not report_path:
        raise HTTPException(status_code=400, detail="No report available. Stop monitoring first to generate a report.")

    if not Path(report_path).exists():
        raise HTTPException(status_code=404, detail="Report file not found.")

    return FileResponse(
        path=report_path,
        filename="ids_final_report.pdf",
        media_type="application/pdf",
    )
