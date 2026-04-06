from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from backend.models import LogEvent
from backend.utils import utc_now


APACHE_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^"]*?) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)
LINUX_AUTH_RE = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[^\[:]+)(?:\[\d+\])?:\s+(?P<message>.+)"
)
WINDOWS_EXPORT_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\|\s+(?P<level>[A-Z]+)\s+\|\s+(?P<source>[^|]+)\|\s+(?P<message>.+)"
)


class LogParser:
    def detect_source_type(self, file_path: str) -> str:
        normalized = file_path.lower()
        if "auth.log" in normalized:
            return "linux_auth"
        if "syslog" in normalized:
            return "linux_syslog"
        if "apache" in normalized or "access.log" in normalized or "nginx" in normalized:
            return "web_access"
        if "windows" in normalized or "security" in normalized:
            return "windows_export"
        return Path(file_path).suffix.lstrip(".") or "generic"

    def parse_line(self, file_path: str, line: str) -> LogEvent:
        source_type = self.detect_source_type(file_path)
        line = line.rstrip("\n")

        if source_type == "web_access":
            parsed = self._parse_web_access(line)
        elif source_type in {"linux_auth", "linux_syslog"}:
            parsed = self._parse_linux_log(line, source_type)
        elif source_type == "windows_export":
            parsed = self._parse_windows_export(line)
        else:
            parsed = {"timestamp": utc_now(), "message": line}

        return LogEvent(
            timestamp=parsed.get("timestamp", utc_now()),
            source=source_type,
            raw=line,
            parsed=parsed,
        )

    def _parse_web_access(self, line: str) -> dict[str, Any]:
        match = APACHE_LOG_RE.match(line)
        if not match:
            return {"timestamp": utc_now(), "message": line}

        data = match.groupdict()
        timestamp = self._parse_apache_timestamp(data["timestamp"])
        return {
            "timestamp": timestamp,
            "ip_address": data["ip"],
            "method": data["method"],
            "path": unquote(data["path"]),
            "protocol": data["protocol"],
            "status_code": int(data["status"]),
            "response_size": data["size"],
            "referrer": data.get("referrer") or "-",
            "user_agent": data.get("agent") or "-",
        }

    def _parse_linux_log(self, line: str, source_type: str) -> dict[str, Any]:
        match = LINUX_AUTH_RE.match(line)
        if not match:
            return {"timestamp": utc_now(), "message": line}

        data = match.groupdict()
        current_year = datetime.now(timezone.utc).year
        timestamp = datetime.strptime(
            f"{current_year} {data['month']} {data['day']} {data['time']}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        parsed: dict[str, Any] = {
            "timestamp": timestamp.isoformat(),
            "host": data["host"],
            "service": data["service"],
            "message": data["message"],
        }

        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", data["message"])
        user_match = re.search(r"user(?:name)?\s+([A-Za-z0-9_.-]+)", data["message"], re.IGNORECASE)
        if ip_match:
            parsed["ip_address"] = ip_match.group(1)
        if user_match:
            parsed["username"] = user_match.group(1)

        lowered = data["message"].lower()
        if "failed password" in lowered:
            parsed["action"] = "failed_login"
        elif "accepted password" in lowered:
            parsed["action"] = "successful_login"
        elif source_type == "linux_syslog":
            parsed["action"] = "system_event"

        return parsed

    def _parse_windows_export(self, line: str) -> dict[str, Any]:
        match = WINDOWS_EXPORT_RE.match(line)
        if not match:
            return {"timestamp": utc_now(), "message": line}

        data = match.groupdict()
        timestamp = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        parsed: dict[str, Any] = {
            "timestamp": timestamp.isoformat(),
            "level": data["level"],
            "source": data["source"].strip(),
            "message": data["message"].strip(),
        }
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", data["message"])
        if ip_match:
            parsed["ip_address"] = ip_match.group(1)
        return parsed

    def _parse_apache_timestamp(self, value: str) -> str:
        try:
            parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            return utc_now()
