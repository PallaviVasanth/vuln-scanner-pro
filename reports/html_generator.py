from typing import List, Dict

def generate_html_report(scan_id: str, findings: List[Dict]) -> str:
    """
    Generate simple HTML report
    """
    html = f"<h1>Scan Report: {scan_id}</h1>"

    for f in findings:
        html += f"""
        <div>
            <h3>{f['type']}</h3>
            <p><b>Endpoint:</b> {f['endpoint']}</p>
            <p><b>Evidence:</b> {f['evidence']}</p>
            <p><b>Confidence:</b> {f.get('confidence')}</p>
        </div>
        """

    return html