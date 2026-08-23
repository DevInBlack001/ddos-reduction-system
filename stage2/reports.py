"""
reports.py: CSV and PDF incident report export routes.
"""

import time
import csv
import logging
from io import StringIO

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

import db
import report_data
import report_pdf

router = APIRouter()


@router.get("/api/logs/export/csv")
def export_csv():
    try:
        conn = db.connect()
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


@router.get("/api/logs/export/pdf")
def export_pdf(hours: float = Query(6.0, ge=(1 / 60), le=168.0)):
    """Renders the incident report entirely from server-side state: the
    logs table, the metrics history, and live enforcement lists. Nothing
    is accepted from the client, so there is no upload to size-cap or
    temp file to clean up."""
    try:
        ctx = report_data.build_context(hours)
        pdf_bytes = report_pdf.render_pdf(ctx)
    except Exception as e:
        logging.error(f"[-] Failed to generate PDF report: {e}")
        raise HTTPException(status_code=500, detail=f"PDF build error: {e}")

    filename = f"flod_system_report_{time.strftime('%Y-%m-%d')}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
