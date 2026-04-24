import nmap
from typing import List, Dict

class PortScanner:
    def __init__(self, target: str):
        self.target = target
        self.scanner = nmap.PortScanner(
            nmap_search_path=(
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                "C:\\Program Files\\Nmap\\nmap.exe"
    )
)

    def scan(self) -> List[Dict]:
        findings = []

        try:
            # Scan common ports
            self.scanner.scan(self.target, arguments="-F")

            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()

                    for port in ports:
                        state = self.scanner[host][proto][port]['state']

                        if state == "open":
                            findings.append({
                                "type": "Open Port",
                                "endpoint": f"{self.target}:{port}",
                                "payload": "N/A",
                                "method": "TCP",
                                "evidence": f"Port {port} is open",
                                "status_code": 0,
                                "response_time": 0,
                                "error_detected": False,
                                "payload_reflected": False
                            })

        except Exception as e:
            print("Nmap scan failed:", e)

        return findings