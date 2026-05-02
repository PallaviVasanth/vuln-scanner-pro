from scanner.core.http_client import HTTPClient
from scanner.core.payload_loader import PayloadLoader
from scanner.core.scanner_base import BaseScanner
from typing import List, Dict

class XSSScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.client = HTTPClient()
        import os
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        payload_path = os.path.join(BASE_DIR, "payloads", "xss_payloads.txt")

        self.payloads = PayloadLoader.load_payloads(payload_path)
    def scan(self) -> List[Dict]:
        findings = []

        for payload in self.payloads:
            params = {"q": payload}

            response = self.client.send_request(self.target, params=params)

            if payload in response["text"]:
                findings.append({
                    "scanner": "Web Scanner",
                    "stage": "Web Vulnerability Scan",
                    "type": "XSS",
                    "endpoint": self.target,
                    "payload": payload,
                    "method": "GET",
                    "evidence": "Payload reflected in response",
                    "status_code": response["status_code"],
                    "response_time": response["response_time"],
                    "error_detected": response["error"],
                    "payload_reflected": True
                })

        return findings