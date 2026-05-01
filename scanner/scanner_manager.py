import requests

from scanner.web.xss_scanner import XSSScanner
from scanner.web.sql_injection import SQLInjectionScanner
from scanner.web.csrf_checker import CSRFChecker
from scanner.web.open_redirect import OpenRedirectScanner
from scanner.web.dir_traversal import DirectoryTraversalScanner
from scanner.web.header_checker import HeaderChecker

from scanner.network.port_scanner import PortScanner
from scanner.network.ssl_checker import SSLChecker


ML_API_URL = "http://localhost:8001//ml/predict"


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
                    finding["scanner"] = scanner.__class__.__name__
                    finding["layer"] = "Web"

                    ml_data = self.call_ml(finding)
                    finding.update(ml_data)

                    all_findings.append(finding)

            except Exception as e:
                print(f"[Web] {scanner.__class__.__name__} failed: {e}")


        # ---- Run Network Scanners ----
        for scanner in network_scanners:
            try:
                results = scanner.scan()

                for finding in results:
                    finding["scanner"] = scanner.__class__.__name__
                    finding["layer"] = "Network"

                    ml_data = self.call_ml(finding)
                    finding.update(ml_data)

                    all_findings.append(finding)

            except Exception as e:
                print(f"[Network] {scanner.__class__.__name__} failed: {e}")


        return all_findings

    def call_ml(self, finding: dict) -> dict:
        ml_payload = {
            "features": {
            "payload":              str(finding.get("payload", "N/A")),
            "response_time":        int(finding.get("response_time", 0)),
            "status_code":          int(finding.get("status_code", 200)),
            "payload_reflected":    bool(finding.get("payload_reflected", False)),
            "error_detected":       bool(finding.get("error_detected", False)),
            "response_length_diff": len(str(finding.get("payload", ""))),
            }
        }
        try:
            res = requests.post(ML_API_URL, json=ml_payload, timeout=5)
            res.raise_for_status()
            return res.json()
        except Exception as e:
            print(f"[ML] call failed: {e}")
            return {
            "prediction":    finding.get("type", "Unknown"),
            "confidence":    0.5,
            "is_vulnerable": finding.get("is_vulnerable", False),
            }