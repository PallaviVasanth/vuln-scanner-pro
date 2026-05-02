from typing import List

class PayloadLoader:
    @staticmethod
    def load_payloads(file_path: str) -> List[str]:
        """
        Load payloads from file
        """
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]