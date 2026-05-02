from scanner.core.http_client import HTTPClient
from scanner.core.payload_loader import PayloadLoader
from scanner.core.scanner_base import BaseScanner
from typing import List, Dict

class DirectoryTraversalScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.client = HTTPClient()
        self.payloads = PayloadLoader.load_payloads("scanner/payloads/traversal_payloads.txt")

    def scan(self) -> List[Dict]:
        findings = []

        for payload in self.payloads:
            params = {"file": payload}

            response = self.client.send_request(self.target, params=params)

            if "root:" in response["text"] or "etc/passwd" in response["text"]:
                findings.append({
                    "type": "Directory Traversal",
                    "endpoint": self.target,
                    "payload": payload,
                    "method": "GET",
                    "evidence": "Sensitive file content detected",
                    "status_code": response["status_code"],
                    "response_time": response["response_time"],
                    "error_detected": False,
                    "payload_reflected": False
                })

        return findings