import logging
from datetime import datetime
from typing import List

import httpx

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 30 #httpx client timeout


class CisaKevFeed(BaseFeed):
    """
    Pulls the CISA Known Exploited Vulnerabilities (KEV) catalog.
    All entries are confirmed actively exploited in the wild, making them
    high priority for triage regardless of CVSS score.
    Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """

    def fetch(self) -> List[ThreatRecord]:
        """
        Fetches the full KEV catalog in a single GET request.
        Returns a ThreatRecord for each entry in the vulnerabilities list.
        """
        url = self.config["url"]
        records: List[ThreatRecord] = []

        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                response = client.get(url)
                response.raise_for_status()
        except httpx.HTTPError as e:
            logger.error("CISA KEV request failed: %s", e)
            return records

        vulnerabilities = response.json().get("vulnerabilities", [])

        for item in vulnerabilities:
            try:
                records.append(self.normalize(item))
            except Exception as e:
                cve_id = item.get("cveID", "unknown")
                logger.error("Failed to normalize KEV entry %s: %s", cve_id, e)

        logger.info("CISA KEV feed fetched %d records", len(records))
        return records

    def normalize(self, raw: dict) -> ThreatRecord:
        """
        Maps a single KEV catalog entry to a ThreatRecord.
        CVSS fields are not available in the KEV catalog.
        Severity is set to 'high' for all entries as all are actively exploited.
        """
        published_at = None
        if raw.get("dateAdded"):
            published_at = datetime.strptime(raw["dateAdded"], "%Y-%m-%d")

        return ThreatRecord(
            cve_id=raw.get("cveID"),
            source="cisa_kev",
            title=raw.get("vulnerabilityName"),
            description=raw.get("shortDescription"),
            cvss_score=None,
            cvss_vector=None,
            severity="high",
            published_at=published_at,
            modified_at=None,
            reference_urls=[],
            raw_data={
                "vendor_project": raw.get("vendorProject"),
                "product": raw.get("product"),
                "required_action": raw.get("requiredAction"),
                "due_date": raw.get("dueDate"),
                "known_ransomware_use": raw.get("knownRansomwareCampaignUse"),
                "notes": raw.get("notes"),
                "cwes": raw.get("cwes", []),
            },
        )