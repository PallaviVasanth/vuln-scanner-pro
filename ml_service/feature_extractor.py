import re
import numpy as np
from typing import Any

# ─────────────────────────────────────────────
# Known attack pattern signatures
# Used to enrich features from payload string alone
# ─────────────────────────────────────────────

SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b)\s+\d+=\d+",        # OR 1=1 / AND 1=1
    r"(?i)(union\s+select)",                    # UNION SELECT
    r"(?i)(drop\s+table|insert\s+into)",        # destructive queries
    r"(?i)(sleep\s*\(|waitfor\s+delay)",        # time-based blind
    r"(?i)(pg_sleep|benchmark\s*\()",           # DB-specific
    r"--\s*$",                                  # SQL comment at end
    r"(?i)(select\s+.*\s+from)",                # SELECT FROM
    r"(?i)(exec\s*\(|xp_cmdshell)",             # command execution
    r"'.*'",                                    # quoted strings
    r"(?i)(information_schema|sys\.tables)",    # schema enumeration
]

XSS_PATTERNS = [
    r"(?i)<script.*?>",                         # script tag
    r"(?i)on\w+\s*=",                           # event handlers onerror= onload=
    r"(?i)<.*?(onerror|onload|onfocus|ontoggle)", # inline events
    r"(?i)javascript\s*:",                       # javascript: URI
    r"(?i)<\s*(iframe|object|embed|svg|body)",  # dangerous tags
    r"(?i)alert\s*\(",                           # alert()
    r"(?i)(document\.cookie|document\.location)", # DOM access
    r"(?i)eval\s*\(",                            # eval()
    r"(?i)<img[^>]+src\s*=\s*['\"]?x",         # broken image XSS
    r"(?i)fetch\s*\(",                           # fetch() exfiltration
]

REDIRECT_PATTERNS = [
    r"(?i)(next|redirect|url|return_to|goto|continue|forward|dest|redir|location|callback|target)\s*=\s*https?://",
    r"(?i)(next|redirect|url|return_to|goto)\s*=\s*//",  # protocol-relative
    r"(?i)redirect_uri\s*=",
]

CSRF_PATTERNS = [
    r"(?i)<form[^>]+method\s*=\s*['\"]?post",  # POST form
    r"(?i)no.csrf.token",
    r"(?i)cross.origin",
    r"(?i)XMLHttpRequest",
    r"(?i)fetch\s*\([^)]+method\s*:\s*['\"]POST",
]


def _count_pattern_matches(payload: str, patterns: list) -> int:
    """Count how many regex patterns match in the payload."""
    return sum(1 for p in patterns if re.search(p, payload))


def _payload_length_score(payload: str) -> float:
    """
    Normalize payload length to 0-1 range.
    Attacks tend to be longer than normal inputs.
    Capped at 500 chars.
    """
    return min(len(payload) / 500.0, 1.0)


def _special_char_density(payload: str) -> float:
    """
    Ratio of special characters (<, >, ', ", ;, --, =) to total length.
    Attacks typically have high special char density.
    """
    if not payload:
        return 0.0
    special = sum(1 for c in payload if c in "<>'\";-=()#")
    return special / len(payload)


# ─────────────────────────────────────────────
# Main extraction function
# ─────────────────────────────────────────────

def extract_features(raw_finding: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a raw scanner finding into a model-ready feature dict.

    Expected input (from API contract / Dev 3 scanner output):
    {
        "payload":              str,
        "response_time":        int,   (milliseconds)
        "status_code":          int,
        "payload_reflected":    bool,
        "error_detected":       bool,
        "response_length_diff": int
    }

    Returns a flat feature dict ready for model prediction.
    """

    payload              = str(raw_finding.get("payload", ""))
    response_time        = int(raw_finding.get("response_time", 0))
    status_code          = int(raw_finding.get("status_code", 200))
    payload_reflected    = bool(raw_finding.get("payload_reflected", False))
    error_detected       = bool(raw_finding.get("error_detected", False))
    response_length_diff = int(raw_finding.get("response_length_diff", 0))

    # ── Pattern match scores ──────────────────
    sqli_score     = _count_pattern_matches(payload, SQLI_PATTERNS)
    xss_score      = _count_pattern_matches(payload, XSS_PATTERNS)
    redirect_score = _count_pattern_matches(payload, REDIRECT_PATTERNS)
    csrf_score     = _count_pattern_matches(payload, CSRF_PATTERNS)

    # ── Payload characteristics ───────────────
    payload_length_score  = _payload_length_score(payload)
    special_char_density  = _special_char_density(payload)

    # ── Status code flags ─────────────────────
    is_500 = int(status_code == 500)
    is_redirect = int(status_code in [301, 302])
    is_forbidden = int(status_code == 403)

    # ── Response time flag ────────────────────
    # Slow response (>300ms) often indicates DB interaction (SQLi)
    is_slow_response = int(response_time > 300)

    return {
        # ── Raw contract fields (numeric) ──────
        "response_time":        response_time,
        "status_code":          status_code,
        "payload_reflected":    int(payload_reflected),
        "error_detected":       int(error_detected),
        "response_length_diff": response_length_diff,

        # ── Derived features ───────────────────
        "sqli_score":            sqli_score,
        "xss_score":             xss_score,
        "redirect_score":        redirect_score,
        "csrf_score":            csrf_score,
        "payload_length_score":  payload_length_score,
        "special_char_density":  special_char_density,
        "is_500":                is_500,
        "is_redirect":           is_redirect,
        "is_forbidden":          is_forbidden,
        "is_slow_response":      is_slow_response,
    }


def get_feature_columns() -> list[str]:
    """
    Returns the ordered list of feature column names.
    Must match exactly what the model was trained on.
    Import this in both train.py and model.py.
    """
    return [
        "response_time",
        "status_code",
        "payload_reflected",
        "error_detected",
        "response_length_diff",
        "sqli_score",
        "xss_score",
        "redirect_score",
        "csrf_score",
        "payload_length_score",
        "special_char_density",
        "is_500",
        "is_redirect",
        "is_forbidden",
        "is_slow_response",
    ]


# ─────────────────────────────────────────────
# Quick test — run directly to verify
# ─────────────────────────────────────────────

if __name__ == "__main__":
    test_cases = [
        {
            "name": "XSS finding",
            "finding": {
                "payload": "<script>alert(1)</script>",
                "response_time": 180,
                "status_code": 200,
                "payload_reflected": True,
                "error_detected": False,
                "response_length_diff": 120,
            }
        },
        {
            "name": "SQLi finding",
            "finding": {
                "payload": "' OR 1=1 --",
                "response_time": 450,
                "status_code": 500,
                "payload_reflected": False,
                "error_detected": True,
                "response_length_diff": 340,
            }
        },
        {
            "name": "Clean request",
            "finding": {
                "payload": "search=laptop&page=1",
                "response_time": 90,
                "status_code": 200,
                "payload_reflected": False,
                "error_detected": False,
                "response_length_diff": 20,
            }
        },
        {
            "name": "Open Redirect",
            "finding": {
                "payload": "?next=http://evil.com",
                "response_time": 110,
                "status_code": 302,
                "payload_reflected": False,
                "error_detected": False,
                "response_length_diff": 50,
            }
        },
    ]

    print("=" * 55)
    print("Feature Extractor — Test Run")
    print("=" * 55)

    for case in test_cases:
        features = extract_features(case["finding"])
        print(f"\n📌 {case['name']}")
        print(f"   Payload : {case['finding']['payload'][:45]}")
        for k, v in features.items():
            print(f"   {k:<25} : {v}")

    print("\n✅ Feature columns:", get_feature_columns())
    print(f"   Total features : {len(get_feature_columns())}")