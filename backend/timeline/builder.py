from __future__ import annotations

from backend.models import AlertEvent, AttackChain, LogEvent, TimelineEvent


class TimelineBuilder:
    def build_from_log(self, event: LogEvent) -> TimelineEvent:
        return TimelineEvent(
            timestamp=event.timestamp,
            event_type="log",
            title=f"Log captured from {event.source}",
            details={
                "source": event.source,
                "raw": event.raw,
                "ip_address": event.parsed.get("ip_address"),
            },
        )

    def build_from_alert(self, alert: AlertEvent) -> TimelineEvent:
        return TimelineEvent(
            timestamp=alert.timestamp,
            event_type="alert",
            title=f"{alert.severity} alert: {alert.category}",
            details={
                "rule_id": alert.rule_id,
                "message": alert.message,
                "ip_address": alert.ip_address,
            },
        )

    def build_from_chain(self, chain: AttackChain) -> TimelineEvent:
        return TimelineEvent(
            timestamp=chain.created_at,
            event_type="attack_chain",
            title=chain.title,
            details={
                "chain_id": chain.chain_id,
                "severity": chain.severity,
                "source_ip": chain.source_ip,
                "step_count": len(chain.steps),
            },
        )
