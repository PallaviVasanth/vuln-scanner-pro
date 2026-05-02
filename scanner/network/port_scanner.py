import socket
from typing import List, Dict

class PortScanner:
    def __init__(self, target: str):
        self.target = target.replace("http://", "").replace("https://", "")

    def scan(self) -> List[Dict]:
        findings = []
        ports = [21, 22, 80, 443, 3306]

        for port in ports:
            try:
                sock = socket.socket()
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()

                if result == 0:
                    findings.append({
                        "scanner": "Network Scanner",
                        "stage": "Port Scanning",
                        "type": "Open Port",
                        "severity": "medium",
                        "confidence": 0.9,
                        "prediction": "Port Exposure",
                        "is_vulnerable": True,
                        "endpoint": self.target,
                        "method": f"Port {port}",
                        "payload": "N/A",
                        "status_code": 0,
                        "response_time": 0,
                        "error_detected": False,       # ← added
                        "payload_reflected": False,    # ← added
                        "evidence": f"Port {port} is open"
                    })
            except:
                continue

        if not findings:
            findings.append({
                "scanner": "Network Scanner",
                "stage": "Port Scanning",
                "type": "Port Scan",
                "severity": "info",
                "confidence": 1.0,
                "prediction": "Safe",
                "is_vulnerable": False,
                "endpoint": self.target,
                "method": "Port Scan",
                "payload": "N/A",
                "status_code": 0,
                "response_time": 0,
                "error_detected": False,
                "payload_reflected": False,
                "evidence": "No open ports detected"
            })

        return findings