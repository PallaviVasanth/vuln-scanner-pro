from scanner.core.http_client import HTTPClient
from scanner.core.scanner_base import BaseScanner
from typing import List, Dict

class HeaderChecker(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.client = HTTPClient()

    def scan(self) -> List[Dict]:
        findings = []

        response = self.client.send_request(self.target)

        headers = response.get("headers", {})

        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ]

        for header in required_headers:
            if header not in headers:
                findings.append({
                    "type": "Security Misconfiguration",
                    "endpoint": self.target,
                    "payload": "N/A",
                    "method": "GET",
                    "evidence": f"{header} header missing",
                    "status_code": response["status_code"],
                    "response_time": response["response_time"],
                    "error_detected": False,
                    "payload_reflected": False
                })

        return findings