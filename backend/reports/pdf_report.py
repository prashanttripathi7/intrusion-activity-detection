from __future__ import annotations

from collections import Counter
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.state import ids_state


class ReportGenerator:
    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> str:
        report_path = self.output_dir / "ids_final_report.pdf"
        document = SimpleDocTemplate(str(report_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        alerts = list(ids_state.alerts)
        timeline = list(ids_state.timeline)
        chains = list(ids_state.attack_chains)
        suspicious_ips = sorted({alert.ip_address for alert in alerts if alert.ip_address})
        category_counter = Counter(alert.category for alert in alerts)

        story.append(Paragraph("Intrusion Activity Detection Report", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Summary", styles["Heading2"]))
        summary_data = [
            ["Metric", "Value"],
            ["Total Logs", str(len(ids_state.logs))],
            ["Total Alerts", str(len(alerts))],
            ["Attack Chains", str(len(chains))],
            ["Suspicious IPs", ", ".join(suspicious_ips) or "None"],
        ]
        story.append(self._styled_table(summary_data))
        story.append(Spacer(1, 12))

        story.append(Paragraph("OWASP Categories", styles["Heading2"]))
        category_data = [["Category", "Count"]]
        for category, count in category_counter.items():
            category_data.append([category, str(count)])
        if len(category_data) == 1:
            category_data.append(["No alerts detected", "0"])
        story.append(self._styled_table(category_data))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Attack Timeline", styles["Heading2"]))
        timeline_data = [["Timestamp", "Type", "Title"]]
        for item in timeline[-20:]:
            timeline_data.append([item.timestamp, item.event_type, item.title])
        if len(timeline_data) == 1:
            timeline_data.append(["-", "-", "No timeline events available"])
        story.append(self._styled_table(timeline_data))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Attack Chains", styles["Heading2"]))
        chain_data = [["Chain ID", "Title", "Severity", "Source IP"]]
        for chain in chains:
            chain_data.append([chain.chain_id, chain.title, chain.severity, chain.source_ip or "Unknown"])
        if len(chain_data) == 1:
            chain_data.append(["-", "No correlated attack chains", "-", "-"])
        story.append(self._styled_table(chain_data))

        document.build(story)
        ids_state.last_report_path = str(report_path)
        return str(report_path)

    def _styled_table(self, data: list[list[str]]) -> Table:
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#eef2ff")]),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ]
            )
        )
        return table


report_generator = ReportGenerator("reports_output")
