from scanner.core.http_client import HTTPClient
from scanner.core.payload_loader import PayloadLoader
from scanner.core.scanner_base import BaseScanner
from typing import List, Dict

class DirectoryTraversalScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.client = HTTPClient()
        import os

        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        payload_path = os.path.join(BASE_DIR, "payloads", "traversal_payloads.txt")

        self.payloads = PayloadLoader.load_payloads(payload_path)
    
    def scan(self) -> List[Dict]:
        findings = []

        for payload in self.payloads:
            params = {"file": payload}

            response = self.client.send_request(self.target, params=params)

            if "root:" in response["text"] or "etc/passwd" in response["text"]:
                findings.append({
                    "scanner": "Web Scanner",
                    "stage": "Web Vulnerability Scan",
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