from __future__ import annotations

import csv
import json
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Any

from backend.models import AlertEvent, LogEvent
from backend.utils import parse_iso_or_fallback


class DatasetPatternExtractor:
    def __init__(self, dataset_dir: str) -> None:
        self.dataset_dir = Path(dataset_dir)
        self.suspicious_ips: set[str] = set()
        self.attack_signatures: list[str] = []
        self.request_threshold_per_minute = 20
        self.request_history: dict[str, deque] = defaultdict(deque)
        self._load_patterns()

    def _load_patterns(self) -> None:
        json_file = self.dataset_dir / "pattern_signatures.json"
        if json_file.exists():
            with json_file.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            self.suspicious_ips.update(data.get("suspicious_ips", []))
            self.attack_signatures.extend(data.get("attack_signatures", []))
            self.request_threshold_per_minute = int(data.get("request_threshold_per_minute", 20))

        csv_file = self.dataset_dir / "cicids_sample.csv"
        if csv_file.exists():
            with csv_file.open("r", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    ip_address = row.get("SourceIP") or row.get("Src IP") or row.get("source_ip")
                    label = (row.get("Label") or row.get("label") or "").lower()
                    signature = row.get("Signature") or row.get("signature")
                    if ip_address and label and label != "benign":
                        self.suspicious_ips.add(ip_address.strip())
                    if signature:
                        self.attack_signatures.append(signature.strip())

        self.attack_signatures = list(dict.fromkeys(signature for signature in self.attack_signatures if signature))

    def convert_dataset_row_to_log(self, row: dict[str, Any]) -> str:
        src_ip = row.get("SourceIP") or row.get("Src IP") or "0.0.0.0"
        method = row.get("Method") or "GET"
        path = row.get("Path") or "/dataset-generated"
        status = row.get("Status") or "200"
        return f'{src_ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 123 "-" "dataset-converter"'

    def analyze(self, event: LogEvent) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        parsed = event.parsed
        raw_lower = event.raw.lower()
        ip_address = parsed.get("ip_address")
        timestamp = parse_iso_or_fallback(event.timestamp)

        if ip_address:
            history = self.request_history[ip_address]
            history.append(timestamp)
            while history and timestamp - history[0] > timedelta(minutes=1):
                history.popleft()

            if ip_address in self.suspicious_ips:
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="DATASET-SUSPICIOUS-IP",
                        category="Dataset Pattern Match",
                        severity="High",
                        source=event.source,
                        message=f"Known suspicious IP matched dataset patterns: {ip_address}.",
                        ip_address=ip_address,
                        metadata={"match_type": "suspicious_ip"},
                    )
                )

            if len(history) >= self.request_threshold_per_minute:
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="DATASET-ABNORMAL-FREQUENCY",
                        category="Dataset Pattern Match",
                        severity="Medium",
                        source=event.source,
                        message=f"Abnormal request rate detected from {ip_address}.",
                        ip_address=ip_address,
                        metadata={
                            "requests_in_last_minute": len(history),
                            "threshold": self.request_threshold_per_minute,
                        },
                    )
                )

        for signature in self.attack_signatures:
            if signature.lower() in raw_lower:
                alerts.append(
                    AlertEvent(
                        timestamp=event.timestamp,
                        rule_id="DATASET-SIGNATURE",
                        category="Dataset Pattern Match",
                        severity="High",
                        source=event.source,
                        message=f"Known attack signature matched dataset pattern: {signature}.",
                        ip_address=ip_address,
                        metadata={"signature": signature},
                    )
                )
                break

        return alerts
