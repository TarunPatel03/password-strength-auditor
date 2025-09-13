from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import mm
from datetime import datetime
from typing import List

from .auditor import AuditResult


def draw_bar(c, x, y, w, h, pct):
    c.setStrokeColor(colors.black)
    c.rect(x, y, w, h)
    c.setFillColor(
        colors.green if pct >= 0.8 else (colors.orange if pct >= 0.5 else colors.red)
    )
    c.rect(x, y, w * pct, h, fill=1, stroke=0)


def render_pdf(results: List[AuditResult], out_path: str):
    c = canvas.Canvas(out_path, pagesize=A4)
    W, H = A4

    c.setTitle("Password Strength Audit Report")
    c.setFont("Helvetica-Bold", 18)
    c.drawString(25 * mm, H - 25 * mm, "Password Strength Audit Report")
    c.setFont("Helvetica", 10)
    c.drawString(
        25 * mm,
        H - 32 * mm,
        f"Generated: {datetime.now().isoformat(sep=' ', timespec='seconds')}",
    )

    y = H - 45 * mm
    for i, r in enumerate(results, 1):
        c.setFont("Helvetica-Bold", 12)
        masked = (
            r.password
            if len(r.password) <= 4
            else (r.password[:2] + "•••" + r.password[-2:])
        )
        c.drawString(25 * mm, y, f"{i}. {masked}")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        c.drawString(
            30 * mm,
            y,
            f"Length: {r.length} | Entropy ≈ {r.entropy:.1f} bits | "
            f"Score: {r.score}/100 | Verdict: {r.verdict}",
        )
        y -= 5 * mm
        breaches = (
            "Skipped"
            if r.hibp_breaches is None
            else (
                "Yes, count=" + str(r.hibp_breaches)
                if r.hibp_breaches > 0
                else "No"
            )
        )
        c.drawString(30 * mm, y, f"HIBP Exposure: {breaches}")
        y -= 5 * mm
        pct = r.score / 100.0
        draw_bar(c, 30 * mm, y - 4 * mm, 120 * mm, 4 * mm, pct)
        y -= 12 * mm

        if y < 30 * mm:
            c.showPage()
            y = H - 25 * mm

    c.save()
