import logging

logger = logging.getLogger(__name__)

SEVERITY_SCORE_MAP = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5
}

VULN_SEVERITY_DEFAULTS = {
    "SQL Injection": "critical",
    "Cross-Site Scripting (XSS)": "high",
    "Open Redirect": "medium",
    "Missing Security Headers": "low",
    "Weak SSL/TLS Configuration": "high",
    "Open Port Detected": "medium",
    "Outdated Software Version": "medium",
    "CSRF Vulnerability": "high",
    "Directory Traversal": "critical",
    "Weak Password Policy": "high",
}

def compute_risk_scores(findings: list) -> list:
    scored = []
    for finding in findings:
        name = finding.get("name", "Unknown")
        severity = finding.get("severity") or VULN_SEVERITY_DEFAULTS.get(name, "low")
        severity = severity.lower()
        cvss_score = SEVERITY_SCORE_MAP.get(severity, 2.0)
        scored.append({
            "name": name,
            "description": finding.get("description", ""),
            "severity": severity,
            "evidence": finding.get("evidence", ""),
            "recommendation": finding.get("recommendation", ""),
            "cvss_score": cvss_score,
        })
        logger.debug(f"Scored vulnerability: {name} => {severity} ({cvss_score})")
    scored.sort(key=lambda x: x["cvss_score"], reverse=True)
    return scored

def get_severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 1.0:
        return "low"
    return "info"

# This file is responsible for vulnerability risk scoring, used for assigning CVSS-like severity scores and ranking findings by risk level, and contains compute_risk_scores, get_severity_from_score, and severity/score mapping tables.