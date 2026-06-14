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
                logger.info(f"{feed.__class__.__name__}: fetched {len(records)} records")
                all_records.extend(records)
            except Exception as e:
                logger.error(f"{feed.__class__.__name__} failed: {e}")

        return self._deduplicate(all_records)

    def _deduplicate(self, records: List[ThreatRecord]) -> List[ThreatRecord]:
        # TODO: deduplicate by cve_id, keeping the record with the most recent modified_at
        # Records without a cve_id (e.g. some OTX pulses) pass through as-is
        raise NotImplementedError
