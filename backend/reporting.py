from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def build_scan_pdf(scan: dict) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 40

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "QuantumShield Report")
    y -= 22
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Domain: {scan.get('domain')}")
    y -= 14
    c.drawString(40, y, f"Scan ID: {scan.get('scan_id')}")
    y -= 14
    c.drawString(40, y, f"Status: {scan.get('status')}  Progress: {scan.get('progress')}%")
    y -= 22

    for finding in scan.get("findings", []):
        if y < 120:
            c.showPage()
            y = h - 40
        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, f"Asset: {finding.get('asset')}")
        y -= 14
        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Score: {finding.get('hndl_risk_score')}  Label: {finding.get('label')}")
        y -= 12
        c.drawString(50, y, f"TLS: {finding.get('tls', {}).get('tls_version')}  Cipher: {finding.get('tls', {}).get('cipher_suite')}")
        y -= 12
        recs = finding.get("recommendations", [])
        for rec in recs[:3]:
            if y < 80:
                c.showPage()
                y = h - 40
            c.drawString(60, y, f"- {rec[:110]}")
            y -= 12
        y -= 8

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()


def readiness_label(avg_risk: float) -> str:
    if avg_risk <= 60:
        return "Transitioning"
    if avg_risk <= 80:
        return "Quantum-Safe"
    return "CRITICAL EXPOSURE"


def build_quantum_certificate(scan: dict, avg_risk: float) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    label = readiness_label(avg_risk)
    y = h - 76

    c.setFillColor(colors.HexColor("#eef3fb"))
    c.roundRect(36, 42, w - 72, h - 84, 22, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#6f8fb9"))
    c.setLineWidth(1.4)
    c.roundRect(44, 50, w - 88, h - 100, 18, fill=0, stroke=1)

    c.setFillColor(colors.HexColor("#2f4f79"))
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(w / 2, y, "QUANTUM READINESS CERTIFICATE")
    y -= 26

    c.setFillColor(colors.HexColor("#5c7697"))
    c.setFont("Helvetica", 11)
    c.drawCentredString(w / 2, y, "Issued by Quanthunt Cyber Risk Intelligence")
    y -= 42

    c.setFillColor(colors.HexColor("#274264"))
    c.setFont("Helvetica-Bold", 15)
    c.drawCentredString(w / 2, y, f"Domain: {scan.get('domain', 'unknown')}")
    y -= 28

    c.setFillColor(colors.HexColor("#3e5d82"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(w / 2, y, f"Scan ID: {scan.get('scan_id', 'n/a')}")
    y -= 22
    c.drawCentredString(w / 2, y, f"Average HNDL Risk Score: {avg_risk:.2f}")
    y -= 30

    if label == "Quantum-Safe":
        c.setFillColor(colors.HexColor("#2b5e4a"))
    elif label == "Transitioning":
        c.setFillColor(colors.HexColor("#7b5b24"))
    else:
        c.setFillColor(colors.HexColor("#7b2b2b"))
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(w / 2, y, f"Readiness Label: {label}")
    y -= 52

    c.setFillColor(colors.HexColor("#455f81"))
    c.setFont("Helvetica", 11)
    c.drawString(84, y, "Reference mappings:")
    y -= 20
    c.drawString(100, y, "- NIST FIPS 203 (ML-KEM)")
    y -= 16
    c.drawString(100, y, "- NIST FIPS 204 (ML-DSA)")
    y -= 16
    c.drawString(100, y, "- NIST FIPS 205 (SLH-DSA)")
    y -= 36

    c.setFillColor(colors.HexColor("#5c7697"))
    c.setFont("Helvetica", 10)
    c.drawString(84, y, "This certificate reflects posture at scan completion time.")
    y -= 14
    c.drawString(84, y, "FIPS/PQC indications are heuristic signals from observed metadata.")
    y -= 14
    c.drawString(84, y, "Use with current CBOM + scan findings for operational decisions.")
    y -= 70

    c.setStrokeColor(colors.HexColor("#7f9fc8"))
    c.line(84, y, 255, y)
    c.line(w - 255, y, w - 84, y)
    c.setFillColor(colors.HexColor("#5c7697"))
    c.setFont("Helvetica", 9)
    c.drawString(84, y - 14, "Issued By Quanthunt")
    c.drawRightString(w - 84, y - 14, "Verification: /api/scan/{scan_id}")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()
