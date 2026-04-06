from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import timedelta

from backend.models import AlertEvent, LogEvent
from backend.utils import parse_iso_or_fallback


class OWASPDetector:
    def __init__(self) -> None:
        self.failed_login_history: dict[str, deque] = defaultdict(deque)
        self.sqli_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"(\bor\b|\band\b)\s+\d=\d",
                r"union\s+select",
                r"select\s+.+\s+from",
                r"drop\s+table",
                r"'--",
                r"information_schema",
                r"sleep\(",
            ]
        ]
        self.path_traversal_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\.\./", r"/etc/passwd", r"/admin", r"/wp-admin", r"/\.git"]
        ]
        self.crypto_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"insecure\s+protocol",
                r"tlsv1\.0",
                r"sslv3",
                r"certificate\s+verify\s+failed",
                r"http://",
                r"weak\s+cipher",
            ]
        ]

    def analyze(self, event: LogEvent) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        alerts.extend(self._detect_broken_access_control(event))
        alerts.extend(self._detect_cryptographic_failures(event))
        alerts.extend(self._detect_injection(event))
        alerts.extend(self._detect_authentication_failures(event))
        return alerts

    def _detect_broken_access_control(self, event: LogEvent) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        parsed = event.parsed
        path = str(parsed.get("path", ""))
        status_code = int(parsed.get("status_code", 0) or 0)
        raw = event.raw

        if status_code in {401, 403}:
            alerts.append(
                AlertEvent(
                    timestamp=event.timestamp,
                    rule_id="OWASP-A01-ACCESS-DENIED",
                    category="A01: Broken Access Control",
                    severity="Medium",
                    source=event.source,
                    message=f"Access denied response detected for path {path or 'unknown'}.",
                    ip_address=parsed.get("ip_address"),
                    metadata={"status_code": status_code, "path": path},
                )
            )

        for pattern in self.path_traversal_patterns:
            if pattern.search(path) or pattern.search(raw):
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="OWASP-A01-PATH-TRAVERSAL",
                        category="A01: Broken Access Control",
                        severity="High",
                        source=event.source,
                        message="Suspicious access control bypass or path traversal attempt detected.",
                        ip_address=parsed.get("ip_address"),
                        metadata={"path": path, "pattern": pattern.pattern},
                    )
                )
                break

        return alerts

    def _detect_cryptographic_failures(self, event: LogEvent) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        parsed = event.parsed
        combined = " ".join(str(value) for value in parsed.values()) + " " + event.raw
        for pattern in self.crypto_patterns:
            if pattern.search(combined):
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="OWASP-A02-CRYPTO",
                        category="A02: Cryptographic Failures",
                        severity="Medium",
                        source=event.source,
                        message="Weak or failed cryptographic control detected in logs.",
                        ip_address=parsed.get("ip_address"),
                        metadata={"matched_pattern": pattern.pattern},
                    )
                )
                break
        return alerts

    def _detect_injection(self, event: LogEvent) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        parsed = event.parsed
        payload = " ".join(
            [
                event.raw,
                str(parsed.get("path", "")),
                str(parsed.get("message", "")),
                str(parsed.get("referrer", "")),
            ]
        )
        for pattern in self.sqli_patterns:
            if pattern.search(payload):
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="OWASP-A03-SQLI",
                        category="A03: Injection",
                        severity="High",
                        source=event.source,
                        message="Potential SQL injection pattern found in request or log message.",
                        ip_address=parsed.get("ip_address"),
                        metadata={"matched_pattern": pattern.pattern, "path": parsed.get("path")},
                    )
                )
                break
        return alerts

    def _detect_authentication_failures(self, event: LogEvent) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        parsed = event.parsed
        ip_address = parsed.get("ip_address") or "unknown"
        username = parsed.get("username")
        action = parsed.get("action")
        timestamp = parse_iso_or_fallback(event.timestamp)

        if action == "failed_login" or "failed password" in event.raw.lower():
            history = self.failed_login_history[ip_address]
            history.append(timestamp)
            while history and timestamp - history[0] > timedelta(minutes=5):
                history.popleft()

            if len(history) >= 5:
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="OWASP-A07-BRUTE-FORCE",
                        category="A07: Identification & Authentication Failures",
                        severity="High",
                        source=event.source,
                        message=f"Brute force pattern detected from {ip_address}.",
                        ip_address=ip_address,
                        metadata={"failed_attempts": len(history), "username": username},
                    )
                )

        if action == "successful_login" and self.failed_login_history.get(ip_address):
            recent_failures = len(self.failed_login_history[ip_address])
            if recent_failures >= 3:
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="OWASP-A07-SUSPICIOUS-SUCCESS",
                        category="A07: Identification & Authentication Failures",
                        severity="High",
                        source=event.source,
                        message=f"Successful login after repeated failures from {ip_address}.",
                        ip_address=ip_address,
                        metadata={"recent_failed_attempts": recent_failures, "username": username},
                    )
                )
        return alerts
