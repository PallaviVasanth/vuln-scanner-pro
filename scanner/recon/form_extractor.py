from bs4 import BeautifulSoup
from scanner.core.http_client import HTTPClient

class FormExtractor:
    def __init__(self, target: str):
        self.target = target
        self.client = HTTPClient()

    def extract_forms(self):
        """
        Extract all forms from HTML
        """
        response = self.client.send_request(self.target)

        soup = BeautifulSoup(response["text"], "html.parser")
        forms = soup.find_all("form")

        return forms