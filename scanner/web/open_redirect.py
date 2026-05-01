from scanner.core.http_client import HTTPClient
from scanner.core.scanner_base import BaseScanner
from typing import List, Dict

class OpenRedirectScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.client = HTTPClient()
        self.payloads = [
            "https://evil.com",
            "//evil.com"
        ]

    def scan(self) -> List[Dict]:
        findings = []

        for payload in self.payloads:
            params = {"redirect": payload}

            response = self.client.send_request(self.target, params=params)

            if "evil.com" in response["text"]:
                findings.append({
                    "scanner": "Web Scanner",
                    "stage": "Web Vulnerability Scan",
                    "type": "Open Redirect",
                    "endpoint": self.target,
                    "payload": payload,
                    "method": "GET",
                    "evidence": "Redirect parameter accepted external URL",
                    "status_code": response["status_code"],
                    "response_time": response["response_time"],
                    "error_detected": False,
                    "payload_reflected": True
                })

        return findings