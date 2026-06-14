from abc import ABC, abstractmethod
from typing import List
from src.ingestion.models import ThreatRecord


class BaseFeed(ABC):
    """
    Abstract base class for all ingestion feed sources.
    Each feed (NVD, CISA, OTX, etc.) implements this interface.
    """

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def fetch(self) -> List[ThreatRecord]:
        """Pull raw data from the feed source and return normalized ThreatRecord objects."""
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: dict) -> ThreatRecord:
        """Convert a raw feed item into a ThreatRecord."""
        raise NotImplementedError

    def is_enabled(self) -> bool:
        return self.config.get("enabled", False)
