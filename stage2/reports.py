"""
reports.py — CSV and PDF incident report export routes.
"""

import os
import time
import csv
import sqlite3
import logging
from io import BytesIO, StringIO

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

import config
import state
import enforcement
from models import PdfReportPayload

router = APIRouter()

MAX_CHART_BASE64_LEN = 8 * 1024 * 1024  # generous headroom over a typical Chart.js canvas PNG export


@router.get("/api/logs/export/csv")
def export_csv():
    try:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification FROM logs ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()

        def _csv_safe(value):
            # Neutralize spreadsheet formula injection (Excel/Sheets treat a
            # leading =, +, -, @, tab, or CR as the start of a formula).
            if isinstance(value, str) and value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
                return "'" + value
            return value

        def iter_csv():
            buf = StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol",
                              "Packet Rate (PPS)", "Shannon Entropy (bits)", "Classification"])
            yield buf.getvalue()
            for r in rows:
                buf.seek(0)
                buf.truncate(0)
                date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[0]))
                writer.writerow([
                    date_str,
                    _csv_safe(r[1]),
                    _csv_safe(r[2] or ""),
                    _csv_safe(r[3] or ""),
                    f"{r[4]:.2f}",
                    f"{r[5]:.4f}",
                    r[6],
                ])
                yield buf.getvalue()

        return StreamingResponse(
            iter_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=shield_gateway_logs.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/logs/export/pdf")
def export_pdf(payload: PdfReportPayload):
    import base64
    import tempfile

    if len(payload.rate_chart_base64) > MAX_CHART_BASE64_LEN or len(payload.entropy_chart_base64) > MAX_CHART_BASE64_LEN:
        raise HTTPException(status_code=413, detail="Chart image payload too large.")

    # Decode charts
    try:
        rate_data = base64.b64decode(payload.rate_chart_base64.split(",")[1])
        entropy_data = base64.b64decode(payload.entropy_chart_base64.split(",")[1])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 chart data: {e}")

    # Unique per-request temp file names -- the old fixed "temp_rate.png"/
    # "temp_entropy.png" paths let two concurrent exports clobber or mix
    # each other's chart images.
    temp_rate_path = None
    temp_entropy_path = None
    pdf_buffer = BytesIO()
    try:
        with tempfile.NamedTemporaryFile(dir=config.SCRIPT_DIR, prefix="pdf_rate_", suffix=".png", delete=False) as f:
            f.write(rate_data)
            temp_rate_path = f.name
        with tempfile.NamedTemporaryFile(dir=config.SCRIPT_DIR, prefix="pdf_entropy_", suffix=".png", delete=False) as f:
            f.write(entropy_data)
            temp_entropy_path = f.name
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decode chart images: {e}")

    try:
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#00a2b0'),
            spaceAfter=15
        )
        subtitle_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#5c7b80'),
            spaceAfter=25
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=10
        )
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            textColor=colors.HexColor('#00a2b0'),
            spaceAfter=8
        )

        elements = []

        # Title
        elements.append(Paragraph("SHIELD GATEWAY INCIDENT REPORT", title_style))
        elements.append(Paragraph(f"GENERATED: {time.strftime('%Y-%m-%d %H:%M:%S')} // SECURE LOG AUDITING", subtitle_style))

        # System Overview Info
        blocked_ips = enforcement.get_blocked_ips()
        overview_data = [
            ["OPERATIONAL MODE", "TRANSPARENT BRIDGE"],
            ["ML CLASSIFIER MODEL", "RANDOM FOREST MULTI-CLASS"],
            ["ACTIVE BLOCKED HOSTS", f"{len(blocked_ips)} IPS IN KERNEL SET"],
            ["CURRENT INTERFACE", "ens19"]
        ]
        t_overview = Table(overview_data, colWidths=[200, 300])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f5fcfd')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#00a2b0')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#111111')),
        ]))
        elements.append(t_overview)
        elements.append(Spacer(1, 20))

        # Embed Chart Images
        elements.append(Paragraph("HISTORICAL ANOMALY GRAPHICS", header_style))
        chart_table_data = [
            [RLImage(temp_rate_path, width=250, height=150), RLImage(temp_entropy_path, width=250, height=150)]
        ]
        t_charts = Table(chart_table_data, colWidths=[270, 270])
        t_charts.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(t_charts)
        elements.append(Spacer(1, 20))

        # Welford Baselines
        elements.append(Paragraph("CURRENT SYSTEM BASELINES", header_style))
        baseline_data = [
            ["METRIC", "CURRENT STATE", "BASELINE LIMITS"],
            ["Rate (PPS)", f"{state.last_metrics.get('ewma_rate', 0.0):.1f} pps", f"μ: {state.last_metrics.get('mean_r', 0.0):.1f} | σ: {state.last_metrics.get('sigma_r', 0.0):.1f} | μ+2σ: {state.last_metrics.get('mean_r', 0.0) + 2 * state.last_metrics.get('sigma_r', 0.0):.1f}"],
            ["Entropy (bits)", f"{state.last_metrics.get('entropy', 0.0):.4f}", f"μ: {state.last_metrics.get('mean_h', 0.0):.4f} | σ: {state.last_metrics.get('sigma_h', 0.0):.4f} | μ-2σ: {state.last_metrics.get('mean_h', 0.0) - 2 * state.last_metrics.get('sigma_h', 0.0):.4f}"],
            ["Protocol Ratios", "TCP / UDP / ICMP", f"{state.last_metrics.get('proto_tcp', 0.0):.1%} / {state.last_metrics.get('proto_udp', 0.0):.1%} / {state.last_metrics.get('proto_icmp', 0.0):.1%}"]
        ]
        t_base = Table(baseline_data, colWidths=[120, 150, 270])
        t_base.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ]))
        elements.append(t_base)
        elements.append(Spacer(1, 20))

        # Blocked IPs
        elements.append(Paragraph(f"ACTIVE MITIGATION TARGETS (TOP 10)", header_style))
        blocked_data = [["BLOCKED IP", "REMAINING TIME (S)"]]
        for b in blocked_ips[:10]:
            blocked_data.append([b["ip"], str(b["remaining_seconds"])])
        if len(blocked_ips) == 0:
            blocked_data.append(["NO ACTIVE BLOCKS", "N/A"])

        t_blocked = Table(blocked_data, colWidths=[300, 240])
        t_blocked.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ]))
        elements.append(t_blocked)
        elements.append(Spacer(1, 20))

        # Recent Logs Table
        elements.append(Paragraph("LATEST RECORDED THREAT METADATA (LAST 100 INCIDENTS)", header_style))

        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, rate, entropy, classification FROM logs ORDER BY id DESC LIMIT 100")
        rows = cursor.fetchall()
        conn.close()

        log_table_data = [["TIMESTAMP", "SOURCE IP", "VICTIM IP", "RATE", "ENTROPY", "CLASSIFICATION"]]
        for r in rows:
            date_str = time.strftime('%H:%M:%S', time.localtime(r[0]))
            log_table_data.append([
                date_str,
                r[1],
                r[2],
                f"{r[3]:.1f} pps",
                f"{r[4]:.4f}",
                r[5].upper()
            ])

        t_logs = Table(log_table_data, colWidths=[80, 100, 100, 80, 80, 100])
        t_logs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('ALIGN', (0,0), (-1,-1), 'CENTER')
        ]))
        elements.append(t_logs)

        # Build PDF
        doc.build(elements)
        pdf_buffer.seek(0)

        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=shield_gateway_report.pdf"}
        )
    except Exception as e:
        logging.error(f"[-] Failed to generate PDF Document: {e}")
        raise HTTPException(status_code=500, detail=f"PDF build error: {e}")
    finally:
        # Clean up temp image files
        if temp_rate_path and os.path.exists(temp_rate_path):
            os.remove(temp_rate_path)
        if temp_entropy_path and os.path.exists(temp_entropy_path):
            os.remove(temp_entropy_path)
