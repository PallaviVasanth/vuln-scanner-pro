import requests

from scanner.web.xss_scanner import XSSScanner
from scanner.web.sql_injection import SQLInjectionScanner
from scanner.web.csrf_checker import CSRFChecker
from scanner.web.open_redirect import OpenRedirectScanner
from scanner.web.dir_traversal import DirectoryTraversalScanner
from scanner.web.header_checker import HeaderChecker

from scanner.network.port_scanner import PortScanner
from scanner.network.ssl_checker import SSLChecker


ML_API_URL = "http://localhost:8001/api/v1/ml/predict"


class ScannerManager:
    def __init__(self, target: str):
        self.target = target

    def run(self):
        all_findings = []

        # 🔹 Web scanners
        web_scanners = [
            XSSScanner(self.target),
            SQLInjectionScanner(self.target),
            CSRFChecker(self.target),
            OpenRedirectScanner(self.target),
            DirectoryTraversalScanner(self.target),
            HeaderChecker(self.target)
        ]

        # 🔹 Network scanners
        network_scanners = [
            PortScanner(self.target),
            SSLChecker(self.target)
        ]

        # ---- Run Web Scanners ----
        for scanner in web_scanners:
            try:
                results = scanner.scan()

                for finding in results:
                    ml_data = self.call_ml(finding)
                    finding.update(ml_data)

                    all_findings.append(finding)

            except Exception as e:
                print(f"Web scanner failed: {e}")

        # ---- Run Network Scanners ----
        for scanner in network_scanners:
            try:
                results = scanner.scan()

                for finding in results:
                    ml_data = self.call_ml(finding)
                    finding.update(ml_data)

                    all_findings.append(finding)

            except Exception as e:
                print(f"Network scanner failed: {e}")
        return all_findings

    def call_ml(self, finding):
        payload = {
            "features": {
                "payload": finding["payload"],
                "response_time": finding["response_time"],
                "status_code": finding["status_code"],
                "payload_reflected": finding["payload_reflected"],
                "error_detected": finding["error_detected"],
                "response_length_diff": len(finding["payload"])
            }
        }

        try:
            res = requests.post(ML_API_URL, json=payload, timeout=5)
            return res.json()

        except Exception:
            return {
                "prediction": finding["type"],
                "confidence": 0.5,
                "is_vulnerable": True
            }