from scanner.core.http_client import HTTPClient

class HeaderGrabber:
    def __init__(self, target: str):
        self.target = target
        self.client = HTTPClient()

    def grab_headers(self):
        """
        Fetch headers from target
        """
        response = self.client.send_request(self.target)

        return {
            "headers": response.get("headers", {}),
            "status_code": response["status_code"]
        }