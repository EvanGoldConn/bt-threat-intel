import logging
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import httpx

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 45 #OTX is slow, if consistently timing out during pagination can try bumping to 60/90s


class OtxFeed(BaseFeed):
    """
    Pulls threat pulse data from AlienVault Open Threat Exchange (OTX).
    Pulses are community-contributed threat intelligence reports that reference
    CVEs, IOCs, and active campaigns.
    Docs: https://otx.alienvault.com/api
    """

    def fetch(self) -> List[ThreatRecord]:
        """
        Fetches OTX pulses modified within the configured lookback window.
        Paginates via the next cursor URL until exhausted.
        Yields one ThreatRecord per CVE indicator found in each pulse.
        Pulses with no CVE indicators yield one record with cve_id=None.
        """
        api_key = os.environ.get("ALIENVAULT_OTX_API_KEY", "")
        base_url = self.config["base_url"]
        pulse_days = self.config.get("pulse_days", 7)

        modified_since = (
            datetime.now(timezone.utc) - timedelta(days=pulse_days)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        headers = {"X-OTX-API-KEY": api_key}
        params = {"modified_since": modified_since}

        records: List[ThreatRecord] = []
        url = f"{base_url}/pulses/subscribed"

        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            while url:
                try:
                    response = client.get(url, headers=headers, params=params)
                    response.raise_for_status()
                except httpx.HTTPError as e:
                    logger.error("OTX request failed: %s", e)
                    break

                data = response.json()

                for pulse in data.get("results", []):
                    try:
                        cve_indicators = [
                            i for i in pulse.get("indicators", [])
                            if i.get("type") == "CVE"
                        ]

                        if cve_indicators:
                            for indicator in cve_indicators:
                                cve_id = indicator.get("indicator")
                                records.append(self.normalize(pulse, cve_id=cve_id))
                        else:
                            records.append(self.normalize(pulse, cve_id=None))

                    except Exception as e:
                        pulse_id = pulse.get("id", "unknown")
                        logger.error("Failed to normalize OTX pulse %s: %s", pulse_id, e)

                # The next field is a full URL with query params already included.
                # Clear params to avoid duplicating them on subsequent requests.
                url = data.get("next")
                params = {}

        logger.info("OTX feed fetched %d records", len(records))
        return records

    def normalize(self, raw: dict, cve_id: Optional[str] = None) -> ThreatRecord:
        """
        Maps an OTX pulse to a ThreatRecord.
        cve_id is passed explicitly because a single pulse can yield multiple records.
        """
        published_at = None
        modified_at = None

        if raw.get("created"):
            published_at = datetime.fromisoformat(
                raw["created"].replace("Z", "+00:00")
            )
        if raw.get("modified"):
            modified_at = datetime.fromisoformat(
                raw["modified"].replace("Z", "+00:00")
            )

        return ThreatRecord(
            cve_id=cve_id,
            source="otx",
            title=raw.get("name"),
            description=raw.get("description"),
            cvss_score=None,
            cvss_vector=None,
            severity=None,
            published_at=published_at,
            modified_at=modified_at,
            reference_urls=raw.get("references", []),
            raw_data={
                "pulse_id": raw.get("id"),
                "author": raw.get("author_name"),
                "tags": raw.get("tags", []),
                "malware_families": raw.get("malware_families", []),
                "targeted_countries": raw.get("targeted_countries", []),
            },
        )