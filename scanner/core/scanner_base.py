from abc import ABC, abstractmethod
from typing import List, Dict

class BaseScanner(ABC):
    def __init__(self, target: str):
        self.target = target

    @abstractmethod
    def scan(self) -> List[Dict]:
        """
        Must return list of vulnerabilities in standard format
        """
        pass