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

                    # Basic validation
                    if not cert:
                        findings.append({
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