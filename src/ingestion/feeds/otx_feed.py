import httpx
from typing import List

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord


class OtxFeed(BaseFeed):
    """
    Pulls threat pulse data from AlienVault Open Threat Exchange (OTX).
    Pulses are community-contributed threat intelligence reports that often
    reference CVEs, IOCs, and active campaigns.
    Docs: https://otx.alienvault.com/api
    """

    def fetch(self) -> List[ThreatRecord]:
        # TODO: GET /api/v1/pulses/subscribed with modified_since param
        # Requires ALIENVAULT_OTX_API_KEY in headers as X-OTX-API-KEY
        # Each pulse may reference multiple CVEs in the indicators list
        raise NotImplementedError

    def normalize(self, raw: dict) -> ThreatRecord:
        # TODO: map OTX pulse fields to ThreatRecord
        # A pulse can contain multiple CVE references; yield one record per CVE
        # Key fields: name, description, created, references, indicators
        raise NotImplementedError
