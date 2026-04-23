import requests
import time
from typing import Dict, Any

class HTTPClient:
    timeout=5  
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def send_request(self, url: str, method: str = "GET", params=None, data=None) -> Dict[str, Any]:
        """
        Sends HTTP request and captures important metrics
        """
        start_time = time.time()
        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                data=data,
                timeout=self.timeout
            )

            response_time = int((time.time() - start_time) * 1000)

            return {
                "status_code": response.status_code,
                "text": response.text,
                "headers": response.headers,  
                "response_time": response_time,
                "error": False
            }

        except Exception as e:
            return {
                "status_code": 0,
                "text": str(e),
                "response_time": 0,
                "error": True
            }