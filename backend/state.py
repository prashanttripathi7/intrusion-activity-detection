from __future__ import annotations

from collections import deque
from typing import Any

from fastapi import WebSocket

from backend.models import AlertEvent, AttackChain, LogEvent, TimelineEvent


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        disconnected: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)


class IDSState:
    def __init__(self) -> None:
        self.logs: deque[LogEvent] = deque(maxlen=2500)
        self.alerts: deque[AlertEvent] = deque(maxlen=1500)
        self.timeline: deque[TimelineEvent] = deque(maxlen=2500)
        self.attack_chains: deque[AttackChain] = deque(maxlen=250)
        self.monitoring_active = False
        self.monitored_files: list[str] = []
        self.source_mode: str = "demo"
        self.scan_mode: str = "live"
        self.last_report_path: str | None = None
        self.manager = ConnectionManager()

    async def add_log(self, event: LogEvent) -> None:
        self.logs.append(event)
        await self.manager.broadcast({"type": "log", "data": event.to_dict()})

    async def add_alert(self, alert: AlertEvent) -> None:
        self.alerts.append(alert)
        await self.manager.broadcast({"type": "alert", "data": alert.to_dict()})

    async def add_timeline_event(self, event: TimelineEvent) -> None:
        self.timeline.append(event)
        await self.manager.broadcast({"type": "timeline", "data": event.to_dict()})

    async def add_attack_chain(self, chain: AttackChain) -> None:
        self.attack_chains.append(chain)
        await self.manager.broadcast({"type": "attack_chain", "data": chain.to_dict()})

    def snapshot(self) -> dict[str, Any]:
        return {
            "monitoring_active": self.monitoring_active,
            "monitored_files": self.monitored_files,
            "source_mode": self.source_mode,
            "scan_mode": self.scan_mode,
            "last_report_path": self.last_report_path,
            "logs": [item.to_dict() for item in self.logs],
            "alerts": [item.to_dict() for item in self.alerts],
            "timeline": [item.to_dict() for item in self.timeline],
            "attack_chains": [item.to_dict() for item in self.attack_chains],
        }


ids_state = IDSState()
