

import logging
import time
import os
from datetime import datetime, timedelta, timezone
import httpx
from typing import List

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord

logger = logging.getLogger(__name__) #creates lgoger named after module [src.ingestion.feeds.nvd_feed]

# NVD enforces a rate limit. Delay between requests to stay compliant.
NVD_REQUEST_DELAY = 0.6

HTTP_TIMEOUT = 30 #httpx client timeout seconds


class NvdFeed(BaseFeed):
    """
    Pulls CVE data from the NVD REST API v2.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """


    def fetch(self) -> List[ThreatRecord]:
        """
        Fetches CVEs published within the configured lookback window.
        Paginates until all matching records are retrieved.
        Max date range allowed by NVD is 120 days.
        """
        api_key = os.environ.get("NVD_API_KEY", "")
        base_url = self.config["base_url"]
        lookback_days = self.config.get("lookback_days", 7)

        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=lookback_days)

        # NVD requires ISO 8601 with milliseconds
        pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        headers = {"apiKey": api_key} if api_key else {}
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        }

        records: List[ThreatRecord] = []
        start_index = 0

        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            while True:
                params["startIndex"] = start_index

                try:
                    response = client.get(base_url, headers=headers, params=params)
                    response.raise_for_status()
                except httpx.HTTPError as e:
                    logger.error("NVD request failed at startIndex %d: %s", start_index, e)
                    break

                data = response.json()
                total = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for item in vulnerabilities:
                    try:
                        record = self.normalize(item["cve"])
                        records.append(record)
                    except Exception as e:
                        cve_id = item.get("cve", {}).get("id", "unknown")
                        logger.error("Failed to normalize CVE %s: %s", cve_id, e)

                start_index += len(vulnerabilities)

                if start_index >= total:
                    break

                time.sleep(NVD_REQUEST_DELAY)

        logger.info("NVD feed fetched %d records", len(records))
        return records
    

    def normalize(self, raw: dict) -> ThreatRecord:
        """
        Maps a single NVD CVE item to a ThreatRecord.
        raw is the dict at vulnerabilities[n]["cve"].
        """
        cve = raw  # raw is already the cve object, passed in from fetch()

        # --- Description: find the English entry ---
        description = None
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value")
                break

        # --- CVSS: try V3.1 -> V3.0 -> V2 in order ---
        cvss_score = None
        cvss_vector = None
        severity = None

        metrics = cve.get("metrics", {})

        if metrics.get("cvssMetricV31"):
            m = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")
            severity = m.get("baseSeverity", "").lower() or None
        elif metrics.get("cvssMetricV30"):
            m = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")
            severity = m.get("baseSeverity", "").lower() or None
        elif metrics.get("cvssMetricV2"):
            m = metrics["cvssMetricV2"][0]
            cvss_score = m["cvssData"].get("baseScore")
            cvss_vector = m["cvssData"].get("vectorString")
            # baseSeverity is outside cvssData in V2
            severity = m.get("baseSeverity", "").lower() or None

        # --- Dates ---
        published_at = None
        modified_at = None
        if cve.get("published"):
            published_at = datetime.fromisoformat(cve["published"])
        if cve.get("lastModified"):
            modified_at = datetime.fromisoformat(cve["lastModified"])

        # --- References ---
        reference_urls = [r["url"] for r in cve.get("references", []) if r.get("url")]

        return ThreatRecord(
            cve_id=cve.get("id"),
            source="nvd",
            title=cve.get("id"),  # NVD has no separate title field; CVE ID is the best identifier
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            published_at=published_at,
            modified_at=modified_at,
            reference_urls=reference_urls,
            raw_data=raw,
        )
