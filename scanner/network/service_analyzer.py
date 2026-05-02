import socket
from typing import List, Dict

class ServiceAnalyzer:
    def __init__(self, target: str):
        self.target = target.replace("http://", "").replace("https://", "")

    def scan(self) -> List[Dict]:
        findings = []

        common_ports = {
            21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL"
        }

        for port, service in common_ports.items():
            try:
                sock = socket.socket()
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()

                if result == 0:
                    findings.append({
                        "scanner": "Network Scanner",
                        "stage": "Service Analysis",
                        "type": f"{service} Service Detected",
                        "severity": "medium" if port in [21, 3306] else "low",
                        "confidence": 0.85,
                        "prediction": "Service Exposure",
                        "is_vulnerable": True if port in [21, 3306] else False,
                        "endpoint": self.target,
                        "method": f"Port {port}",
                        "payload": "N/A",
                        "status_code": 0,
                        "response_time": 0,
                        "evidence": f"Port {port} ({service}) is open"
                    })

            except Exception:
                continue

        # If nothing found
        if not findings:
            findings.append({
                "scanner": "Network Scanner",
                "stage": "Service Analysis",
                "type": "Service Scan",
                "severity": "info",
                "confidence": 1.0,
                "prediction": "Safe",
                "is_vulnerable": False,
                "endpoint": self.target,
                "method": "Port Scan",
                "payload": "N/A",
                "status_code": 0,
                "response_time": 0,
                "evidence": "No risky services detected"
            })

        return findings