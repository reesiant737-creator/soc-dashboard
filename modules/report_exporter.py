import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER


SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc3545"),
    "HIGH": colors.HexColor("#fd7e14"),
    "MEDIUM": colors.HexColor("#ffc107"),
    "LOW": colors.HexColor("#17a2b8"),
    "NONE": colors.HexColor("#6c757d"),
}


def export_json_siem(scan_data: dict, alerts: list, techniques: list, ai_report: str) -> str:
    """Export structured JSON suitable for SIEM ingestion."""
    payload = {
        "schema_version": "1.0",
        "export_time": datetime.now().isoformat(),
        "report_type": "network_scan_soc_report",
        "scan_metadata": {
            "scan_time": scan_data.get("scan_time"),
            "total_hosts": scan_data.get("total_hosts", 0),
            "scanner": "nmap",
        },
        "hosts": [
            {
                "ip": h["ip"],
                "hostname": h.get("hostname"),
                "mac": h.get("mac"),
                "os": h.get("os", {}),
                "risk_score": h.get("risk_score", 0),
                "max_cvss": h.get("max_cvss", 0.0),
                "open_ports": [
                    {"port": p["port"], "service": p["service"], "product": p.get("product", "")}
                    for p in h.get("ports", []) if p.get("state") == "open"
                ],
                "cves": h.get("cves", [])[:5],
            }
            for h in scan_data.get("hosts", [])
        ],
        "alerts": alerts,
        "mitre_techniques": techniques,
        "ai_analysis": ai_report,
        "severity_summary": {
            "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "HIGH": sum(1 for a in alerts if a["severity"] == "HIGH"),
            "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "LOW": sum(1 for a in alerts if a["severity"] == "LOW"),
        }
    }
    return json.dumps(payload, indent=2, default=str)


def export_pdf_report(scan_data: dict, alerts: list, techniques: list,
                      ai_report: str, output_path: str) -> str:
    """Generate a professional SOC incident report PDF."""
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                            rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 fontSize=20, textColor=colors.HexColor("#1a1a2e"),
                                 spaceAfter=6)
    h1_style = ParagraphStyle("h1", parent=styles["Heading1"],
                               fontSize=14, textColor=colors.HexColor("#dc3545"),
                               spaceBefore=12, spaceAfter=6)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"],
                               fontSize=11, textColor=colors.HexColor("#343a40"), spaceBefore=8)
    body_style = styles["Normal"]
    body_style.fontSize = 9

    story.append(Paragraph("SOC INCIDENT REPORT", title_style))
    story.append(Paragraph(f"Network Vulnerability Assessment", styles["Heading2"]))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#dc3545")))
    story.append(Spacer(1, 12))

    sev = {
        "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "HIGH": sum(1 for a in alerts if a["severity"] == "HIGH"),
        "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        "LOW": sum(1 for a in alerts if a["severity"] == "LOW"),
    }
    summary_data = [
        ["Metric", "Value"],
        ["Total Hosts Scanned", str(scan_data.get("total_hosts", 0))],
        ["Total Alerts", str(len(alerts))],
        ["Critical Alerts", str(sev["CRITICAL"])],
        ["High Alerts", str(sev["HIGH"])],
        ["MITRE Techniques", str(len(set(t["technique_id"] for t in techniques)))],
    ]
    t = Table(summary_data, colWidths=[3*inch, 2*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(Paragraph("EXECUTIVE SUMMARY", h1_style))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("AI ANALYST ASSESSMENT", h1_style))
    for line in ai_report.split("\n"):
        line = line.strip()
        if not line:
            story.append(Spacer(1, 4))
        elif line.startswith("##") or line.startswith("**"):
            story.append(Paragraph(line.replace("**", "").replace("#", "").strip(), h2_style))
        else:
            story.append(Paragraph(line, body_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("TOP ALERTS", h1_style))
    alert_data = [["Severity", "Rule", "Host", "Description"]]
    for a in sorted(alerts, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"]))[:20]:
        alert_data.append([a["severity"], a["rule_name"][:25], a["host_ip"], a["description"][:40]])

    if len(alert_data) > 1:
        at = Table(alert_data, colWidths=[1*inch, 1.8*inch, 1.2*inch, 2.5*inch])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff3cd"), colors.white]),
        ]))
        story.append(at)

    doc.build(story)
    return output_path
