import logging
from typing import List

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord
from src.ingestion.feeds.nvd_feed import NvdFeed
from src.ingestion.feeds.cisa_kev_feed import CisaKevFeed
from src.ingestion.feeds.otx_feed import OtxFeed
from src.ingestion.feeds.exploitdb_feed import ExploitDbFeed
from src.ingestion.feeds.github_poc_feed import GithubPocFeed

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """
    Orchestrates all feed pullers. Runs each enabled feed, collects
    ThreatRecord output, deduplicates by CVE ID, and passes records
    to the storage layer.
    """

    def __init__(self, feed_config: dict):
        self.feeds: List[BaseFeed] = [
            NvdFeed(feed_config.get("nvd", {})),
            CisaKevFeed(feed_config.get("cisa_kev", {})),
            OtxFeed(feed_config.get("alienvault_otx", {})),
            ExploitDbFeed(feed_config.get("exploitdb", {})),
            GithubPocFeed(feed_config.get("github_poc", {})),
        ]

    def run(self) -> List[ThreatRecord]:
        """Run all enabled feeds and return deduplicated records."""
        all_records: List[ThreatRecord] = []

        for feed in self.feeds:
            if not feed.is_enabled():
                continue
            try:
                records = feed.fetch()
                logger.info("%s: fetched %d records", feed.__class__.__name__, len(records))
                all_records.extend(records)
            except Exception as e:
                logger.error("%s failed: %s", feed.__class__.__name__, e)

        return self._deduplicate(all_records)

    def _deduplicate(self, records: List[ThreatRecord]) -> List[ThreatRecord]:
        """
        Deduplicates records by cve_id, keeping the record with the most recent
        modified_at. Records with no cve_id pass through without deduplication
        since there is no reliable key to deduplicate against.
        """
        seen: dict = {}
        no_cve: List[ThreatRecord] = []

        for record in records:
            if record.cve_id is None:
                no_cve.append(record)
                continue

            existing = seen.get(record.cve_id)

            if existing is None:
                seen[record.cve_id] = record
            else:
                # Prefer the record with the more recent modified_at.
                # If either record lacks modified_at, keep the existing entry.
                if record.modified_at and existing.modified_at:
                    if record.modified_at > existing.modified_at:
                        seen[record.cve_id] = record

        deduplicated = list(seen.values()) + no_cve
        logger.info(
            "Deduplication: %d records in, %d out (%d no-cve passthrough)",
            len(records),
            len(deduplicated),
            len(no_cve),
        )
        return deduplicated
