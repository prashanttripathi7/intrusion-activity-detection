from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from backend.correlation.engine import CorrelationEngine
from backend.detector.dataset_patterns import DatasetPatternExtractor
from backend.detector.owasp_rules import OWASPDetector
from backend.models import LogEvent
from backend.models import TimelineEvent
from backend.parser.log_parser import LogParser
from backend.reports.pdf_report import report_generator
from backend.realtime.system_sources import (
    SystemLogSourceResolver,
    WindowsEventCollector,
    parse_windows_event_timestamp,
)
from backend.state import ids_state
from backend.timeline.builder import TimelineBuilder
from backend.utils import parse_iso_or_fallback
from backend.utils import utc_now


class RealtimeMonitor:
    def __init__(self) -> None:
        self.parser = LogParser()
        self.owasp_detector = OWASPDetector()
        self.dataset_detector = DatasetPatternExtractor("datasets")
        self.correlation_engine = CorrelationEngine()
        self.timeline_builder = TimelineBuilder()
        self.source_resolver = SystemLogSourceResolver()
        self.windows_event_collector = WindowsEventCollector()
        self.monitor_task: asyncio.Task | None = None
        self.file_offsets: dict[str, int] = {}
        self.source_mode = "demo"
        self.scan_mode = "live"
        self.session_started_at: datetime | None = None

    async def start(
        self,
        file_paths: list[str] | None = None,
        mode: str = "auto",
        scan_mode: str = "live",
    ) -> dict[str, str]:
        if ids_state.monitoring_active:
            return {"status": "already_running"}

        self.scan_mode = scan_mode if scan_mode in {"live", "historical"} else "live"
        self.session_started_at = datetime.now(timezone.utc) if self.scan_mode == "live" else None
        selected_mode = self._resolve_mode(file_paths=file_paths, mode=mode)
        selected_files = file_paths or (
            self.source_resolver.resolve_default_files() if selected_mode == "file" else self._default_sample_files()
        )

        ids_state.monitoring_active = True
        ids_state.logs.clear()
        ids_state.alerts.clear()
        ids_state.timeline.clear()
        ids_state.attack_chains.clear()
        ids_state.monitored_files = selected_files
        ids_state.source_mode = selected_mode
        ids_state.scan_mode = self.scan_mode
        self.source_mode = selected_mode
        self._initialize_offsets(selected_files)
        self._initialize_windows_event_position()
        if self.scan_mode == "historical" and self.source_mode != "windows_events":
            await self._bootstrap_existing_logs(selected_files)
        if self.scan_mode == "historical" and self.source_mode == "windows_events":
            await self._poll_windows_events(limit=200)
        self.monitor_task = asyncio.create_task(self._monitor_loop(selected_files))
        await ids_state.add_timeline_event(
            TimelineEvent(
                timestamp=utc_now(),
                event_type="monitoring",
                title="Realtime monitoring started",
                details={
                    "files": selected_files,
                    "mode": self.source_mode or "unknown",
                    "scan_mode": self.scan_mode,
                },
            )
        )
        return {"status": "started", "mode": self.source_mode, "scan_mode": self.scan_mode}

    async def stop(self) -> dict[str, str]:
        if not ids_state.monitoring_active:
            return {"status": "already_stopped"}

        ids_state.monitoring_active = False
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
            self.monitor_task = None

        await ids_state.add_timeline_event(
            TimelineEvent(
                timestamp=utc_now(),
                event_type="monitoring",
                title="Realtime monitoring stopped",
                details={
                    "files": ids_state.monitored_files,
                    "mode": self.source_mode or "unknown",
                    "scan_mode": self.scan_mode,
                },
            )
        )
        report_generator.generate()
        self.session_started_at = None
        return {"status": "stopped"}

    async def _monitor_loop(self, file_paths: list[str]) -> None:
        while ids_state.monitoring_active:
            if self.source_mode == "windows_events":
                await self._poll_windows_events(limit=20)
            else:
                for file_path in file_paths:
                    await self._read_new_lines(file_path)
            await asyncio.sleep(1)

    async def _bootstrap_existing_logs(self, file_paths: list[str]) -> None:
        for file_path in file_paths:
            path = Path(file_path)
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    stripped = line.strip()
                    if stripped:
                        await self._process_line(file_path, stripped)
            self.file_offsets[file_path] = path.stat().st_size

    async def _poll_windows_events(self, limit: int) -> None:
        for log_name in self.source_resolver.windows_event_logs():
            for record in self.windows_event_collector.fetch_new_events(log_name, limit=limit):
                if not self._is_current_session_windows_event(record.timestamp):
                    continue
                synthetic_line = (
                    f"{record.timestamp} | {record.level.upper()} | {record.source} | {record.message}"
                )
                event = self.parser.parse_line(f"{log_name.lower()}_windows_security.txt", synthetic_line)
                event.parsed["log_name"] = record.log_name
                event.parsed["record_id"] = record.record_id
                await self._handle_event(event)

    async def _read_new_lines(self, file_path: str) -> None:
        path = Path(file_path)
        if not path.exists():
            return

        last_offset = self.file_offsets.get(file_path, 0)
        with path.open("r", encoding="utf-8") as handle:
            handle.seek(last_offset)
            new_lines = handle.readlines()
            self.file_offsets[file_path] = handle.tell()

        for line in new_lines:
            stripped = line.strip()
            if stripped:
                await self._process_line(file_path, stripped)

    async def _process_line(self, file_path: str, line: str) -> None:
        event = self.parser.parse_line(file_path, line)
        if not self._is_current_session_file_event(event.timestamp):
            return
        await self._handle_event(event)

    async def _handle_event(self, event: LogEvent) -> None:
        await ids_state.add_log(event)
        await ids_state.add_timeline_event(self.timeline_builder.build_from_log(event))

        alerts = self.owasp_detector.analyze(event) + self.dataset_detector.analyze(event)
        for alert in alerts:
            await ids_state.add_alert(alert)
            await ids_state.add_timeline_event(self.timeline_builder.build_from_alert(alert))
            chain = self.correlation_engine.process_alert(alert)
            if chain:
                await ids_state.add_attack_chain(chain)
                await ids_state.add_timeline_event(self.timeline_builder.build_from_chain(chain))

    def _initialize_offsets(self, file_paths: list[str]) -> None:
        self.file_offsets.clear()
        for file_path in file_paths:
            path = Path(file_path)
            if self.scan_mode == "historical":
                self.file_offsets[file_path] = 0
            else:
                self.file_offsets[file_path] = path.stat().st_size if path.exists() else 0

    def _initialize_windows_event_position(self) -> None:
        if self.source_mode != "windows_events":
            return
        self.windows_event_collector.last_record_ids.clear()
        if self.scan_mode == "live":
            for log_name in self.source_resolver.windows_event_logs():
                self.windows_event_collector.prime_latest_record_id(log_name)

    def _default_sample_files(self) -> list[str]:
        return [
            str(Path("sample_logs") / "auth.log"),
            str(Path("sample_logs") / "apache_access.log"),
            str(Path("sample_logs") / "windows_security.txt"),
        ]

    def _resolve_mode(self, file_paths: list[str] | None, mode: str) -> str:
        if file_paths:
            return "file"
        if mode == "demo":
            return "demo"
        if mode == "auto":
            resolved = self.source_resolver.default_mode()
            if resolved == "file" and not self.source_resolver.resolve_default_files():
                return "demo"
            return resolved
        return mode

    def _is_current_session_windows_event(self, timestamp: str) -> bool:
        if self.session_started_at is None:
            return True
        return parse_windows_event_timestamp(timestamp) >= self.session_started_at

    def _is_current_session_file_event(self, timestamp: str) -> bool:
        if self.session_started_at is None:
            return True
        return parse_iso_or_fallback(timestamp) >= self.session_started_at


realtime_monitor = RealtimeMonitor()
