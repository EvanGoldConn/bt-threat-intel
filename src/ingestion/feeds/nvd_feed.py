import httpx
from typing import List

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord

# NVD enforces a rate limit. Delay between requests to stay compliant.
NVD_REQUEST_DELAY = 0.6


class NvdFeed(BaseFeed):
    """
    Pulls CVE data from the NVD REST API v2.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """

    def fetch(self) -> List[ThreatRecord]:
        # TODO: implement paginated fetch with lookback window
        # Use self.config["lookback_days"] to set the pubStartDate param
        # Handle rate limiting with NVD_REQUEST_DELAY between requests
        raise NotImplementedError

    def normalize(self, raw: dict) -> ThreatRecord:
        # TODO: map NVD CVE item structure to ThreatRecord
        # Key fields: cveMetadata.cveId, descriptions[0].value,
        # metrics.cvssMetricV31[0].cvssData.baseScore, published, lastModified
        raise NotImplementedError
