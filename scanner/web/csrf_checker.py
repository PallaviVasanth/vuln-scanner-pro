from scanner.core.http_client import HTTPClient
from scanner.core.scanner_base import BaseScanner
from bs4 import BeautifulSoup
from typing import List, Dict

class CSRFChecker(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.client = HTTPClient()

    def scan(self) -> List[Dict]:
        findings = []

        response = self.client.send_request(self.target)

        soup = BeautifulSoup(response["text"], "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            inputs = form.find_all("input")
            csrf_token_found = any("csrf" in (inp.get("name") or "").lower() for inp in inputs)

            if not csrf_token_found:
                findings.append({
                    "type": "CSRF",
                    "endpoint": self.target,
                    "payload": "N/A",
                    "method": "POST",
                    "evidence": "No CSRF token found in form",
                    "status_code": response["status_code"],
                    "response_time": response["response_time"],
                    "error_detected": False,
                    "payload_reflected": False
                })

        return findings