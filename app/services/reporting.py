from __future__ import annotations

import csv
import io
import json

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def scan_json(scan) -> bytes:
    payload = {
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "score": scan.security_score,
            "grade": scan.grade,
            "resources": scan.resource_count,
            "findings": scan.finding_count,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "resource": finding.resource_address,
                "category": finding.category,
                "framework": finding.framework,
                "control_id": finding.control_id,
                "evidence": json.loads(finding.evidence or "{}"),
                "remediation": finding.remediation,
            }
            for finding in scan.findings
        ],
    }
    return json.dumps(payload, indent=2, default=str).encode()


def scan_csv(scan) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Finding ID", "Title", "Severity", "Status", "Resource", "Category", "Framework", "Control", "Risk Score", "Remediation"])
    for finding in scan.findings:
        writer.writerow([finding.id, finding.title, finding.severity, finding.status, finding.resource_address, finding.category, finding.framework, finding.control_id or "", finding.risk_score, finding.remediation])
    return output.getvalue().encode()


def scan_pdf(scan) -> bytes:
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=14 * mm, leftMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("CloudSentinel Security Assessment", styles["Title"]),
        Spacer(1, 8),
        Paragraph(f"<b>Scan:</b> {scan.name}", styles["BodyText"]),
        Paragraph(f"<b>Security score:</b> {scan.security_score}/100 (Grade {scan.grade})", styles["BodyText"]),
        Paragraph(f"<b>Resources:</b> {scan.resource_count} &nbsp;&nbsp; <b>Findings:</b> {scan.finding_count}", styles["BodyText"]),
        Spacer(1, 12),
    ]
    rows = [["Severity", "Finding", "Resource", "Framework"]]
    for finding in scan.findings[:80]:
        rows.append([finding.severity.upper(), Paragraph(finding.title, styles["BodyText"]), Paragraph(finding.resource_address, styles["BodyText"]), finding.control_id or finding.framework])
    table = Table(rows, colWidths=[22 * mm, 62 * mm, 72 * mm, 25 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102b42")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#a0afba")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef4f7")]),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    return output.getvalue()
