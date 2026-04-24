from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.state import ids_state
from backend.utils import utc_now


class ReportGenerator:
    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> str:
        report_path = self.output_dir / "ids_final_report.pdf"
        document = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            leftMargin=16 * mm,
            rightMargin=16 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
        )

        styles = self._build_styles()
        story = []

        alerts = list(ids_state.alerts)
        timeline = list(ids_state.timeline)
        chains = list(ids_state.attack_chains)
        suspicious_ips = sorted({alert.ip_address for alert in alerts if alert.ip_address})
        category_counter = Counter(alert.category for alert in alerts)
        severity_counter = Counter(alert.severity for alert in alerts)
        generated_at = self._format_timestamp(utc_now())

        story.append(Paragraph("Intrusion Activity Detection Report", styles["cover_title"]))
        story.append(Spacer(1, 6))
        story.append(
            Paragraph(
                "A concise incident summary generated from the IDS runtime state, including alerts, correlation results, suspicious IPs, and recent timeline activity.",
                styles["cover_subtitle"],
            )
        )
        story.append(Spacer(1, 12))
        story.append(
            self._styled_table(
                [
                    ["Generated At", generated_at],
                    ["Scan Mode", ids_state.scan_mode.title()],
                    ["Source Mode", ids_state.source_mode.replace("_", " ").title()],
                    ["Monitoring Status", "Stopped"],
                ],
                widths=[36 * mm, 130 * mm],
                header=False,
            )
        )
        story.append(Spacer(1, 14))

        story.append(Paragraph("Executive Summary", styles["section_title"]))
        story.append(
            self._styled_table(
                [
                    ["Metric", "Value"],
                    ["Total Logs", str(len(ids_state.logs))],
                    ["Total Alerts", str(len(alerts))],
                    ["Attack Chains", str(len(chains))],
                    ["Suspicious IPs", ", ".join(suspicious_ips[:6]) or "None detected"],
                ],
                widths=[52 * mm, 114 * mm],
            )
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("Severity Breakdown", styles["section_title"]))
        story.append(
            self._styled_table(
                [
                    ["High", str(severity_counter.get("High", 0))],
                    ["Medium", str(severity_counter.get("Medium", 0))],
                    ["Low", str(severity_counter.get("Low", 0))],
                ],
                widths=[83 * mm, 83 * mm],
                header=False,
                accent="severity",
            )
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("OWASP Category Summary", styles["section_title"]))
        category_rows = [["Category", "Count"]]
        for category, count in category_counter.items():
            category_rows.append([category, str(count)])
        if len(category_rows) == 1:
            category_rows.append(["No alerts detected", "0"])
        story.append(self._styled_table(category_rows, widths=[126 * mm, 40 * mm]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Recent Alerts", styles["section_title"]))
        recent_alert_rows = [["Time", "Severity", "Category", "Message"]]
        for alert in alerts[-8:]:
            recent_alert_rows.append(
                [
                    self._format_timestamp(alert.timestamp),
                    alert.severity,
                    alert.category,
                    self._shorten(alert.message, 140),
                ]
            )
        if len(recent_alert_rows) == 1:
            recent_alert_rows.append(["-", "-", "No alerts", "No alert activity captured"])
        story.append(self._styled_table(recent_alert_rows, widths=[28 * mm, 20 * mm, 46 * mm, 72 * mm]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Attack Timeline", styles["section_title"]))
        timeline_rows = [["Timestamp", "Type", "Title"]]
        for item in timeline[-16:]:
            timeline_rows.append(
                [
                    self._format_timestamp(item.timestamp),
                    item.event_type.replace("_", " ").title(),
                    self._shorten(item.title, 90),
                ]
            )
        if len(timeline_rows) == 1:
            timeline_rows.append(["-", "-", "No timeline events available"])
        story.append(self._styled_table(timeline_rows, widths=[30 * mm, 30 * mm, 106 * mm]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Correlated Attack Chains", styles["section_title"]))
        chain_rows = [["Chain ID", "Severity", "Source IP", "Summary"]]
        for chain in chains:
            step_summary = " | ".join(step["rule_id"] for step in chain.steps[:4])
            chain_rows.append(
                [
                    chain.chain_id,
                    chain.severity,
                    chain.source_ip or "Unknown",
                    self._shorten(step_summary or chain.title, 120),
                ]
            )
        if len(chain_rows) == 1:
            chain_rows.append(["-", "-", "-", "No correlated attack chains"])
        story.append(self._styled_table(chain_rows, widths=[24 * mm, 22 * mm, 34 * mm, 86 * mm]))

        document.build(story)
        ids_state.last_report_path = str(report_path)
        return str(report_path)

    def _build_styles(self) -> dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {
            "cover_title": ParagraphStyle(
                "cover_title",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=24,
                leading=28,
                textColor=colors.HexColor("#111827"),
                alignment=TA_LEFT,
            ),
            "cover_subtitle": ParagraphStyle(
                "cover_subtitle",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=10.2,
                leading=15,
                textColor=colors.HexColor("#4b5563"),
            ),
            "section_title": ParagraphStyle(
                "section_title",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=17,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=6,
            ),
        }

    def _styled_table(
        self,
        data: list[list[str]],
        widths: list[float],
        header: bool = True,
        accent: str = "default",
    ) -> Table:
        wrapped_data = self._wrap_table_data(data, header)
        table = Table(wrapped_data, colWidths=widths, repeatRows=1 if header else 0)
        palette = {
            "default": (colors.HexColor("#172554"), colors.HexColor("#eff6ff"), colors.HexColor("#dbeafe")),
            "severity": (colors.HexColor("#1f2937"), colors.HexColor("#f8fafc"), colors.HexColor("#e2e8f0")),
        }
        header_bg, row_a, row_b = palette[accent]
        styles = [
            ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.8),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]

        if header:
            styles.extend(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [row_a, row_b]),
                ]
            )
        else:
            styles.extend(
                [
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [row_a, row_b]),
                ]
            )

        table.setStyle(TableStyle(styles))
        return table

    def _wrap_table_data(self, data: list[list[str]], header: bool) -> list[list[Paragraph]]:
        styles = getSampleStyleSheet()
        header_style = ParagraphStyle(
            "table_header",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.8,
            leading=11,
            textColor=colors.white,
        )
        cell_style = ParagraphStyle(
            "table_cell",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.6,
            leading=11,
            textColor=colors.HexColor("#0f172a"),
        )

        wrapped_rows: list[list[Paragraph]] = []
        for row_index, row in enumerate(data):
            style = header_style if header and row_index == 0 else cell_style
            wrapped_rows.append([Paragraph(self._escape(value), style) for value in row])
        return wrapped_rows

    def _format_timestamp(self, value: str) -> str:
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed.strftime("%d %b %Y, %I:%M %p")
        except ValueError:
            return value

    def _shorten(self, value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        return value[: limit - 3].rstrip() + "..."

    def _escape(self, value: str) -> str:
        return (
            str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )


report_generator = ReportGenerator("reports_output")
