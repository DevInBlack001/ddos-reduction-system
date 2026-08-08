"""
reports.py — CSV and PDF incident report export routes.
"""

import os
import time
import csv
import math
import uuid
import sqlite3
import logging
from io import BytesIO, StringIO
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, String as RLString
from reportlab.pdfgen import canvas as pdfcanvas

import config
import state
import enforcement
from auth import get_session_username
from storage import load_json_file
from models import PdfReportPayload

router = APIRouter()

MAX_CHART_BASE64_LEN = 8 * 1024 * 1024  # generous headroom over a typical Chart.js canvas PNG export

MAX_DIAGRAM_SOURCES = 14
MAX_DIAGRAM_VICTIMS = 6
MAX_IP_LABEL_LEN = 28

STATUS_COLORS = {
    "blocked": colors.HexColor('#dc3545'),
    "ratelimited": colors.HexColor('#f59e0b'),
    "whitelisted": colors.HexColor('#16a34a'),
    "normal": colors.HexColor('#00a2b0'),
}
VICTIM_COLOR = colors.HexColor('#7c3aed')
DIAGRAM_BG = colors.HexColor('#f5fcfd')
DIAGRAM_BORDER = colors.HexColor('#dddddd')
LABEL_COLOR = colors.HexColor('#333333')


@router.get("/api/logs/export/csv")
def export_csv():
    try:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification FROM logs ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()

        def _csv_safe(value):
            if isinstance(value, str) and value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
                return "'" + value
            return value

        def iter_csv():
            buf = StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Timestamp (UTC)", "Source IP", "Destination IP", "Protocol",
                              "Packet Rate (PPS)", "Shannon Entropy (bits)", "Classification"])
            yield buf.getvalue()
            for r in rows:
                buf.seek(0)
                buf.truncate(0)
                date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(r[0]))
                writer.writerow([
                    date_str,
                    _csv_safe(r[1]),
                    _csv_safe(r[2] or ""),
                    _csv_safe(r[3] or ""),
                    f"{r[4]:.2f}" if r[4] is not None else "",
                    f"{r[5]:.4f}",
                    r[6],
                ])
                yield buf.getvalue()

        return StreamingResponse(
            iter_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=flod_system_logs.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------------------------------------------------------
# Server-side topology snapshot (shared by both diagrams)
# -----------------------------------------------------------------------------

def _clip_ip(ip: str) -> str:
    ip = str(ip)
    return ip if len(ip) <= MAX_IP_LABEL_LEN else ip[:MAX_IP_LABEL_LEN - 1] + "…"


def _status_for(ip, blocked, ratelimited, whitelisted):
    if ip in blocked:
        return "blocked"
    if ip in ratelimited:
        return "ratelimited"
    if ip in whitelisted:
        return "whitelisted"
    return "normal"


def _load_topology():
    flows = []
    if os.path.exists(config.FLOWS_PATH):
        try:
            with open(config.FLOWS_PATH, "r") as f:
                flows = (__import__("json").load(f) or {}).get("active_ips", [])
        except Exception:
            flows = []

    victims_raw = load_json_file(config.VICTIMS_PATH, [])
    configured_victims = [v.get("ip") for v in victims_raw if isinstance(v, dict) and v.get("ip")]

    blocked = {b["ip"] for b in enforcement.get_blocked_ips()}
    ratelimited = {r["ip"] for r in enforcement.get_ratelimited_ips()}
    whitelisted = set(load_json_file(config.WHITELIST_PATH, []))

    source_rates = {}
    edge_rates = {}
    for f in flows:
        if not isinstance(f, dict):
            continue
        src, dst = f.get("ip"), f.get("dst")
        if not src or not dst:
            continue
        try:
            rate = float(f.get("rate", 0.0))
        except (TypeError, ValueError):
            rate = 0.0
        source_rates[src] = source_rates.get(src, 0.0) + rate
        key = (src, dst)
        edge_rates[key] = edge_rates.get(key, 0.0) + rate

    top_sources = sorted(source_rates.items(), key=lambda kv: -kv[1])[:MAX_DIAGRAM_SOURCES]
    top_source_ips = {ip for ip, _ in top_sources}

    edges = [
        {"src": src, "dst": dst, "rate": rate, "status": _status_for(src, blocked, ratelimited, whitelisted)}
        for (src, dst), rate in edge_rates.items()
        if src in top_source_ips
    ]

    seen_dsts = list(dict.fromkeys(e["dst"] for e in edges))
    victims = (configured_victims or seen_dsts)[:MAX_DIAGRAM_VICTIMS]

    return {
        "sources": top_sources,
        "victims": victims,
        "edges": [e for e in edges if e["dst"] in victims],
        "blocked": blocked,
        "ratelimited": ratelimited,
        "whitelisted": whitelisted,
    }


def _build_traffic_diagram(topo, width=250, height=190):
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, fillColor=DIAGRAM_BG, strokeColor=DIAGRAM_BORDER, strokeWidth=0.5))

    sources, victims = topo["sources"], topo["victims"]
    margin_x, top_pad, bottom_pad = 46, 14, 10
    src_n, vic_n = max(1, len(sources)), max(1, len(victims))
    src_spacing = (height - top_pad - bottom_pad) / src_n
    vic_spacing = (height - top_pad - bottom_pad) / vic_n

    src_pos = {ip: (margin_x, height - top_pad - src_spacing * (i + 0.5)) for i, (ip, _) in enumerate(sources)}
    vic_pos = {ip: (width - margin_x, height - top_pad - vic_spacing * (i + 0.5)) for i, ip in enumerate(victims)}

    for e in topo["edges"]:
        a, b = src_pos.get(e["src"]), vic_pos.get(e["dst"])
        if not a or not b:
            continue
        color = STATUS_COLORS.get(e["status"], STATUS_COLORS["normal"])
        end = b
        if e["status"] == "blocked":
            end = (a[0] + (b[0] - a[0]) * 0.65, a[1] + (b[1] - a[1]) * 0.65)
        line = Line(a[0], a[1], end[0], end[1], strokeColor=color, strokeWidth=min(2.5, 0.4 + math.log10(1 + e["rate"])))
        if e["status"] != "normal":
            line.strokeDashArray = [3, 2]
        d.add(line)

    for ip, (x, y) in src_pos.items():
        status = _status_for(ip, topo["blocked"], topo["ratelimited"], topo["whitelisted"])
        d.add(Circle(x, y, 3, fillColor=STATUS_COLORS.get(status, STATUS_COLORS["normal"]), strokeColor=colors.white, strokeWidth=0.5))
        d.add(RLString(x - 6, y - 2, _clip_ip(ip), fontSize=5.5, fillColor=LABEL_COLOR, textAnchor='end'))

    for ip, (x, y) in vic_pos.items():
        d.add(Circle(x, y, 5, fillColor=VICTIM_COLOR, strokeColor=colors.white, strokeWidth=0.5))
        d.add(RLString(x + 7, y - 2, _clip_ip(ip), fontSize=5.5, fillColor=LABEL_COLOR, textAnchor='start'))

    if not sources and not victims:
        d.add(RLString(width / 2, height / 2, "No active flows", fontSize=8, fillColor=LABEL_COLOR, textAnchor='middle'))

    return d


def _build_network_diagram(topo, width=250, height=190):
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, fillColor=DIAGRAM_BG, strokeColor=DIAGRAM_BORDER, strokeWidth=0.5))

    sources, victims = topo["sources"], topo["victims"]
    cx, cy = width * 0.66, height / 2
    n_v = max(1, len(victims))
    v_gap = min(18, (height - 20) / n_v)
    victim_pos = {ip: (cx, cy + (i - (n_v - 1) / 2) * v_gap) for i, ip in enumerate(victims)}

    radius = min(cx - 26, height / 2 - 12, 80)
    n_s = len(sources)
    source_pos = {}
    for i, (ip, _rate) in enumerate(sources):
        t = i / (n_s - 1) if n_s > 1 else 0.5
        angle = math.radians(100 + t * 160)
        source_pos[ip] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))

    for e in topo["edges"]:
        a, b = source_pos.get(e["src"]), victim_pos.get(e["dst"])
        if not a or not b:
            continue
        color = STATUS_COLORS.get(e["status"], STATUS_COLORS["normal"])
        end = b
        if e["status"] == "blocked":
            end = (a[0] + (b[0] - a[0]) * 0.65, a[1] + (b[1] - a[1]) * 0.65)
        line = Line(a[0], a[1], end[0], end[1], strokeColor=color, strokeWidth=min(2.2, 0.4 + math.log10(1 + e["rate"])))
        if e["status"] != "normal":
            line.strokeDashArray = [3, 2]
        d.add(line)

    for ip, (x, y) in source_pos.items():
        status = _status_for(ip, topo["blocked"], topo["ratelimited"], topo["whitelisted"])
        d.add(Circle(x, y, 3, fillColor=STATUS_COLORS.get(status, STATUS_COLORS["normal"]), strokeColor=colors.white, strokeWidth=0.5))
        d.add(RLString(x - 5, y - 2, _clip_ip(ip), fontSize=5, fillColor=LABEL_COLOR, textAnchor='end'))

    for ip, (x, y) in victim_pos.items():
        d.add(Circle(x, y, 6, fillColor=VICTIM_COLOR, strokeColor=colors.white, strokeWidth=0.6))
        d.add(RLString(x + 9, y - 2, _clip_ip(ip), fontSize=5.5, fillColor=LABEL_COLOR, textAnchor='start'))

    if not sources and not victims:
        d.add(RLString(width / 2, height / 2, "No active flows", fontSize=8, fillColor=LABEL_COLOR, textAnchor='middle'))

    return d


def _legend_table():
    row = ["", "Source (normal)", "", "Rate-limited", "", "Blocked", "", "Victim"]
    t = Table([row], colWidths=[9, 82, 9, 72, 9, 60, 9, 55])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), STATUS_COLORS["normal"]),
        ('BACKGROUND', (2, 0), (2, 0), STATUS_COLORS["ratelimited"]),
        ('BACKGROUND', (4, 0), (4, 0), STATUS_COLORS["blocked"]),
        ('BACKGROUND', (6, 0), (6, 0), VICTIM_COLOR),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#555555')),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
    ]))
    return t


class _ReportCanvas(pdfcanvas.Canvas):
    """Adds the confidential footer + "Page N of M" -- needs a two-pass
    canvas since the total page count isn't known until layout finishes."""

    def __init__(self, *args, report_id="", generated_by="unknown", **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []
        self._report_id = report_id
        self._generated_by = generated_by

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for saved in self._saved_page_states:
            self.__dict__.update(saved)
            self._draw_chrome(page_count)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_chrome(self, page_count):
        width, _height = letter
        self.saveState()
        self.setStrokeColor(DIAGRAM_BORDER)
        self.setLineWidth(0.5)
        self.line(36, 40, width - 36, 40)
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor('#888888'))
        self.drawString(36, 28, f"FLOD System — CONFIDENTIAL — {self._report_id}")
        self.drawCentredString(width / 2, 28, f"Generated by {self._generated_by}")
        self.drawRightString(width - 36, 28, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


@router.post("/api/logs/export/pdf")
def export_pdf(payload: PdfReportPayload, request: Request):
    import base64
    import tempfile

    generated_by = get_session_username(request)

    for field in (payload.rate_chart_base64, payload.entropy_chart_base64):
        if field and len(field) > MAX_CHART_BASE64_LEN:
            raise HTTPException(status_code=413, detail="Chart image payload too large.")

    try:
        rate_data = base64.b64decode(payload.rate_chart_base64.split(",")[1])
        entropy_data = base64.b64decode(payload.entropy_chart_base64.split(",")[1])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 chart data: {e}")

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
        report_id = f"FLOD-{uuid.uuid4().hex[:12].upper()}"
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontName='Helvetica-Bold',
                                      fontSize=20, textColor=colors.HexColor('#00a2b0'), spaceAfter=4)
        subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontName='Helvetica',
                                         fontSize=10, textColor=colors.HexColor('#5c7b80'), spaceAfter=15)
        body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontName='Helvetica',
                                     fontSize=9.5, textColor=colors.HexColor('#333333'), leading=14, spaceAfter=10)
        header_style = ParagraphStyle('HeaderStyle', parent=styles['Normal'], fontName='Helvetica-Bold',
                                       fontSize=11, textColor=colors.HexColor('#00a2b0'), spaceAfter=8)

        elements = []

        banner = Table([["CONFIDENTIAL — INTERNAL USE ONLY — GENERATED FOR AUTHORIZED PERSONNEL"]], colWidths=[540])
        banner.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1c2b33')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(banner)
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("FLOD SYSTEM INCIDENT REPORT", title_style))
        elements.append(Paragraph("Adaptive Two-Stage Layer-4 Volumetric DDoS Mitigation Gateway", subtitle_style))

        meta_data = [
            ["REPORT ID", report_id, "GENERATED", time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())],
            ["GENERATED BY", generated_by, "CLASSIFICATION", "CONFIDENTIAL"],
        ]
        t_meta = Table(meta_data, colWidths=[90, 170, 90, 190])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5fcfd')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#111111')),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_meta)
        elements.append(Spacer(1, 18))

        blocked_ips = enforcement.get_blocked_ips()
        ratelimited_ips = enforcement.get_ratelimited_ips()
        classification = xml_escape(str(state.last_metrics.get('latest_classification', 'Normal')))
        victims_configured = load_json_file(config.VICTIMS_PATH, [])
        elements.append(Paragraph("EXECUTIVE SUMMARY", header_style))
        elements.append(Paragraph(
            f"This report summarizes the operational and security posture of the FLOD System "
            f"mitigation platform as of the generation timestamp above. The active classifier "
            f"currently reports a <b>{classification}</b> state across {len(victims_configured)} "
            f"monitored target(s), with <b>{len(blocked_ips)}</b> host(s) under an active hard "
            f"block and <b>{len(ratelimited_ips)}</b> host(s) under active rate-limiting "
            f"enforcement. Details for each mitigation tier follow below.",
            body_style
        ))
        elements.append(Spacer(1, 10))

        ingress_iface, egress_iface = config.get_sniffer_interfaces()
        overview_data = [
            ["OPERATIONAL MODE", "TRANSPARENT BRIDGE"],
            ["ML CLASSIFIER MODEL", "RANDOM FOREST MULTI-CLASS"],
            ["ACTIVE BLOCKED HOSTS", f"{len(blocked_ips)} IPS IN KERNEL SET"],
            ["INGRESS INTERFACE", (ingress_iface or "NOT CONFIGURED").upper()],
            ["EGRESS INTERFACE", (egress_iface or "NOT CONFIGURED").upper()]
        ]
        t_overview = Table(overview_data, colWidths=[200, 300])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5fcfd')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00a2b0')),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#111111')),
        ]))
        elements.append(t_overview)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("HISTORICAL ANOMALY GRAPHICS", header_style))
        chart_table_data = [
            [RLImage(temp_rate_path, width=250, height=150), RLImage(temp_entropy_path, width=250, height=150)]
        ]
        t_charts = Table(chart_table_data, colWidths=[270, 270])
        t_charts.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(t_charts)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("NETWORK TOPOLOGY & TRAFFIC FLOW", header_style))
        topo = _load_topology()
        network_drawing = _build_network_diagram(topo)
        traffic_drawing = _build_traffic_diagram(topo)
        t_maps = Table([[network_drawing, traffic_drawing]], colWidths=[270, 270])
        t_maps.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(t_maps)
        elements.append(Spacer(1, 6))
        elements.append(_legend_table())
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("CURRENT SYSTEM BASELINES", header_style))
        baseline_data = [
            ["METRIC", "CURRENT STATE", "BASELINE LIMITS"],
            ["Rate (PPS)", f"{state.last_metrics.get('ewma_rate', 0.0):.1f} pps", f"μ: {state.last_metrics.get('mean_r', 0.0):.1f} | σ: {state.last_metrics.get('sigma_r', 0.0):.1f} | μ+2σ: {state.last_metrics.get('mean_r', 0.0) + 2 * state.last_metrics.get('sigma_r', 0.0):.1f}"],
            ["Entropy (bits)", f"{state.last_metrics.get('entropy', 0.0):.4f}", f"μ: {state.last_metrics.get('mean_h', 0.0):.4f} | σ: {state.last_metrics.get('sigma_h', 0.0):.4f} | μ-2σ: {state.last_metrics.get('mean_h', 0.0) - 2 * state.last_metrics.get('sigma_h', 0.0):.4f}"],
            ["Protocol Ratios", "TCP / UDP / ICMP", f"{state.last_metrics.get('proto_tcp', 0.0):.1%} / {state.last_metrics.get('proto_udp', 0.0):.1%} / {state.last_metrics.get('proto_icmp', 0.0):.1%}"]
        ]
        t_base = Table(baseline_data, colWidths=[120, 150, 270])
        t_base.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9f9f9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
        ]))
        elements.append(t_base)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("ACTIVE MITIGATION TARGETS (TOP 10)", header_style))
        blocked_data = [["BLOCKED IP", "REMAINING TIME (S)"]]
        for b in blocked_ips[:10]:
            blocked_data.append([b["ip"], str(b["remaining_seconds"])])
        if len(blocked_ips) == 0:
            blocked_data.append(["NO ACTIVE BLOCKS", "N/A"])

        t_blocked = Table(blocked_data, colWidths=[300, 240])
        t_blocked.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9f9f9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
        ]))
        elements.append(t_blocked)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("LATEST RECORDED THREAT METADATA (LAST 100 INCIDENTS)", header_style))

        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, rate, entropy, classification FROM logs ORDER BY id DESC LIMIT 100")
        rows = cursor.fetchall()
        conn.close()

        log_table_data = [["TIME (UTC)", "SOURCE IP", "VICTIM IP", "RATE", "ENTROPY", "CLASSIFICATION"]]
        for r in rows:
            date_str = time.strftime('%H:%M:%S', time.gmtime(r[0]))
            log_table_data.append([
                date_str,
                r[1],
                r[2],
                f"{r[3]:.1f} pps" if r[3] is not None else "n/a",
                f"{r[4]:.4f}",
                r[5].upper()
            ])

        t_logs = Table(log_table_data, colWidths=[80, 100, 100, 80, 80, 100])
        t_logs.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9f9f9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))
        elements.append(t_logs)

        canvas_maker = lambda *a, **kw: _ReportCanvas(*a, report_id=report_id, generated_by=generated_by, **kw)
        doc.build(elements, canvasmaker=canvas_maker)
        pdf_buffer.seek(0)

        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=flod_system_report.pdf"}
        )
    except Exception as e:
        logging.error(f"[-] Failed to generate PDF Document: {e}")
        raise HTTPException(status_code=500, detail=f"PDF build error: {e}")
    finally:
        for p in (temp_rate_path, temp_entropy_path):
            if p and os.path.exists(p):
                os.remove(p)
