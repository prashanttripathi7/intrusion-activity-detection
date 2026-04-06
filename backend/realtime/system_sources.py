from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class WindowsEventRecord:
    timestamp: str
    level: str
    source: str
    message: str
    record_id: int
    log_name: str


class SystemLogSourceResolver:
    def __init__(self) -> None:
        self.host_os = platform.system().lower()

    def default_mode(self) -> str:
        return "windows_events" if self.host_os == "windows" else "file"

    def resolve_default_files(self) -> list[str]:
        candidates: list[Path] = []
        if self.host_os == "linux":
            candidates = [
                Path("/var/log/auth.log"),
                Path("/var/log/syslog"),
                Path("/var/log/nginx/access.log"),
                Path("/var/log/apache2/access.log"),
                Path("/var/log/httpd/access_log"),
            ]
        elif self.host_os == "darwin":
            candidates = [Path("/var/log/system.log")]

        return [str(path) for path in candidates if path.exists()]

    def windows_event_logs(self) -> list[str]:
        return ["Security", "System", "Application"]


class WindowsEventCollector:
    def __init__(self) -> None:
        self.last_record_ids: dict[str, int] = {}

    def fetch_new_events(self, log_name: str, limit: int = 20) -> list[WindowsEventRecord]:
        script = f"""
$events = Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, LevelDisplayName, ProviderName, Id, Message, RecordId, LogName |
    Sort-Object RecordId
if ($events) {{
    $events | ConvertTo-Json -Depth 4 -Compress
}}
"""
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
        )
        raw_output = completed.stdout.strip()
        if completed.returncode != 0 or not raw_output:
            return []

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return []

        if isinstance(parsed, dict):
            items = [parsed]
        else:
            items = parsed

        last_seen = self.last_record_ids.get(log_name, 0)
        records: list[WindowsEventRecord] = []

        for item in items:
            record_id = int(item.get("RecordId") or 0)
            if record_id <= last_seen:
                continue

            timestamp = str(item.get("TimeCreated") or "")
            level = str(item.get("LevelDisplayName") or "INFO")
            source = str(item.get("ProviderName") or log_name)
            message = " ".join(str(item.get("Message") or "").splitlines()).strip()
            records.append(
                WindowsEventRecord(
                    timestamp=timestamp,
                    level=level,
                    source=source,
                    message=message,
                    record_id=record_id,
                    log_name=log_name,
                )
            )

        if items:
            newest = max(int(item.get("RecordId") or 0) for item in items)
            self.last_record_ids[log_name] = max(last_seen, newest)

        return records

    def prime_latest_record_id(self, log_name: str) -> None:
        script = f"""
$event = Get-WinEvent -LogName '{log_name}' -MaxEvents 1 -ErrorAction SilentlyContinue |
    Select-Object RecordId
if ($event) {{
    $event | ConvertTo-Json -Compress
}}
"""
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
        )
        raw_output = completed.stdout.strip()
        if completed.returncode != 0 or not raw_output:
            return

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return

        record_id = int(parsed.get("RecordId") or 0)
        self.last_record_ids[log_name] = record_id


def parse_windows_event_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if not normalized:
        return datetime.now(timezone.utc)

    for candidate in (
        normalized,
        normalized.replace("Z", "+00:00"),
    ):
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue

    return datetime.now(timezone.utc)
