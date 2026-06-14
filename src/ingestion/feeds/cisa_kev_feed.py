import httpx
from typing import List

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord


class CisaKevFeed(BaseFeed):
    """
    Pulls the CISA Known Exploited Vulnerabilities (KEV) catalog.
    All entries are confirmed actively exploited in the wild, making them
    high priority for triage regardless of CVSS score.
    Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """

    def fetch(self) -> List[ThreatRecord]:
        # TODO: GET self.config["url"], parse the vulnerabilities list
        # Each entry has: cveID, vendorProject, product, vulnerabilityName,
        # dateAdded, shortDescription, requiredAction, dueDate
        raise NotImplementedError

    def normalize(self, raw: dict) -> ThreatRecord:
        # TODO: map KEV entry fields to ThreatRecord
        # Note: KEV does not include CVSS scores directly.
        # dateAdded and requiredAction are valuable metadata to preserve in raw_data.
        raise NotImplementedError
