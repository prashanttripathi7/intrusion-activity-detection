from __future__ import annotations

from collections import defaultdict

from backend.models import AlertEvent, AttackChain
from backend.utils import utc_now


class CorrelationEngine:
    def __init__(self) -> None:
        self.alert_history_by_ip: dict[str, list[AlertEvent]] = defaultdict(list)
        self.chain_counter = 0

    def process_alert(self, alert: AlertEvent) -> AttackChain | None:
        ip_address = alert.ip_address or "unknown"
        history = self.alert_history_by_ip[ip_address]
        history.append(alert)
        recent = history[-6:]
        categories = {item.category for item in recent}
        rule_ids = {item.rule_id for item in recent}

        if "OWASP-A07-BRUTE-FORCE" in rule_ids and "OWASP-A07-SUSPICIOUS-SUCCESS" in rule_ids:
            return self._build_chain(
                title="Brute force followed by successful access",
                severity="High",
                source_ip=ip_address,
                alerts=recent,
            )

        if "OWASP-A03-SQLI" in rule_ids and any(item.rule_id.startswith("OWASP-A01") for item in recent):
            return self._build_chain(
                title="Injection attempt followed by access control probing",
                severity="High",
                source_ip=ip_address,
                alerts=recent,
            )

        if any(item.rule_id.startswith("DATASET-") for item in recent) and any(
            item.rule_id.startswith("OWASP-A07") for item in recent
        ):
            return self._build_chain(
                title="Dataset-informed hostile activity chain",
                severity="High",
                source_ip=ip_address,
                alerts=recent,
            )

        if "A03: Injection" in categories and "A01: Broken Access Control" in categories:
            return self._build_chain(
                title="Web exploitation chain",
                severity="High",
                source_ip=ip_address,
                alerts=recent,
            )

        return None

    def _build_chain(
        self,
        title: str,
        severity: str,
        source_ip: str | None,
        alerts: list[AlertEvent],
    ) -> AttackChain:
        self.chain_counter += 1
        return AttackChain(
            chain_id=f"CHAIN-{self.chain_counter:04d}",
            title=title,
            severity=severity,
            source_ip=source_ip,
            created_at=utc_now(),
            steps=[
                {
                    "timestamp": alert.timestamp,
                    "rule_id": alert.rule_id,
                    "category": alert.category,
                    "message": alert.message,
                }
                for alert in alerts[-4:]
            ],
        )
