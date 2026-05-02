import ssl
import socket
from typing import List, Dict

class SSLChecker:
    def __init__(self, target: str):
        self.target = target.replace("https://", "").replace("http://", "")

    def scan(self) -> List[Dict]:
        findings = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        findings.append({
                            "scanner": "SSLChecker",
                            "stage": "SSL Inspection",
                            "type": "SSL Valid",
                            "endpoint": self.target,
                            "payload": "N/A",
                            "method": "TLS",
                            "evidence": "Valid SSL certificate",
                            "status_code": 200,
                            "response_time": 0,
                            "error_detected": False,
                            "payload_reflected": False
                        })

                    # Basic validation
                    if not cert:
                        findings.append({
                            "scanner": "Network Scanner",
                            "stage": "SSL Inspection",
                            "type": "SSL Issue",
                            "endpoint": self.target,
                            "payload": "N/A",
                            "method": "TLS",
                            "evidence": "No SSL certificate found",
                            "status_code": 0,
                            "response_time": 0,
                            "error_detected": True,
                            "payload_reflected": False
                        })

        except Exception as e:
            findings.append({
                "scanner": "Network Scanner",
                "stage": "SSL Inspection",
                "type": "SSL Issue",
                "endpoint": self.target,
                "payload": "N/A",
                "method": "TLS",
                "evidence": str(e),
                "status_code": 0,
                "response_time": 0,
                "error_detected": True,
                "payload_reflected": False
            })

        return findings