from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(scan_id: str, findings: list, output_path: str):
    """
    Generate PDF report for vulnerabilities
    """
    doc = SimpleDocTemplate(output_path)
    styles = getSampleStyleSheet()

    content = []

    content.append(Paragraph(f"Scan Report: {scan_id}", styles["Title"]))

    for f in findings:
        content.append(Paragraph(f"<b>{f['type']}</b>", styles["Heading2"]))
        content.append(Paragraph(f"Endpoint: {f['endpoint']}", styles["Normal"]))
        content.append(Paragraph(f"Evidence: {f['evidence']}", styles["Normal"]))
        content.append(Paragraph(f"Confidence: {f.get('confidence', 'N/A')}", styles["Normal"]))

    doc.build(content)