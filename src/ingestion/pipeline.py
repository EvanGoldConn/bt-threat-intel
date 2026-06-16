import logging
from typing import List, Optional, Tuple

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord
from src.ingestion.feeds.nvd_feed import NvdFeed
from src.ingestion.feeds.cisa_kev_feed import CisaKevFeed
from src.ingestion.feeds.otx_feed import OtxFeed
from src.ingestion.feeds.exploitdb_feed import ExploitDbFeed
from src.ingestion.feeds.github_poc_feed import GithubPocFeed
from src.ingestion.store import ThreatStore
from src.ingestion.embeddings import build_embedding_text, embed_text, store_embedding
from src.analysis.triage import CveTriage
from src.analysis.ttp_mapper import TtpMapper

logger = logging.getLogger(__name__)

ANALYSIS_BATCH_LIMIT = 50

# _store_records returns (ThreatRecord, threat_id) tuples rather than just records.
# The threat_id is the PostgreSQL row id assigned on upsert, needed to link
# triage and TTP results back to the correct threat_records row.

# _analyze_new_records gates on three conditions before calling the LLM:
# no cve_id, no description, or already present in ttp_mappings.
# Records failing any condition are skipped without an API call.
# Triage and TTP mapping run independently per record so a failure in one
# does not block the other from saving.


class IngestionPipeline:
    """
    Orchestrates all feed pullers. Runs each enabled feed, collects
    ThreatRecord output, deduplicates by CVE ID, stores records,
    generates embeddings, and runs LLM analysis on new records only.
    """

    def __init__(self, feed_config: dict):
        self.feeds: List[BaseFeed] = [
            NvdFeed(feed_config.get("nvd", {})),
            CisaKevFeed(feed_config.get("cisa_kev", {})),
            OtxFeed(feed_config.get("alienvault_otx", {})),
            ExploitDbFeed(feed_config.get("exploitdb", {})),
            GithubPocFeed(feed_config.get("github_poc", {})),
        ]
        self.store = ThreatStore()
        self.triage = CveTriage()
        self.ttp_mapper = TtpMapper()

    def run(self) -> List[ThreatRecord]:
        """
        Runs all enabled feeds, deduplicates records, stores them,
        generates embeddings, and runs LLM analysis on new records.
        Returns the deduplicated list of ThreatRecords.
        """
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

        deduplicated = self._deduplicate(all_records)
        stored = self._store_records(deduplicated)
        self._embed_records(stored)
        self._analyze_new_records(stored)
        return deduplicated

    def _store_records(self, records: List[ThreatRecord]) -> List[Tuple[ThreatRecord, int]]:
        """
        Upserts each record into PostgreSQL.
        Returns a list of (ThreatRecord, threat_id) tuples for records that stored successfully.
        """
        stored = []
        for record in records:
            threat_id = self.store.upsert_record(record)
            if threat_id is not None:
                stored.append((record, threat_id))
        return stored

    def _embed_records(self, stored: List[Tuple[ThreatRecord, int]]) -> None:
        """
        Generates and stores embeddings for records that have not been embedded yet.
        Skips records that already have a row in threat_embeddings.
        Embedding text is built from sanitized fields via build_embedding_text().
        The embedded text is external untrusted data. At retrieval time in the RAG
        chat pipeline, retrieved chunks must be wrapped in XML delimiter tags and
        the system prompt must treat them as untrusted context to defend against
        indirect prompt injection via poisoned embeddings.
        """
        # TODO: apply XML delimiter wrapping and untrusted data instruction in
        # src/chat/pipeline.py when retrieved embedding chunks are passed to the
        # LLM as context. This is the primary RAG poisoning defense point.
        embedded = 0
        skipped = 0

        for record, threat_id in stored:
            if self.store.embedding_exists(threat_id):
                skipped += 1
                continue
            try:
                embedding_text = build_embedding_text(record)
                vector = embed_text(embedding_text)
                if vector:
                    store_embedding(threat_id, vector)
                    embedded += 1
            except Exception:
                logger.error("Embedding failed for %s", record.cve_id, exc_info=True)

        logger.info("Embeddings complete: %d embedded, %d skipped", embedded, skipped)

    def _analyze_new_records(self, stored: List[Tuple[ThreatRecord, int]]) -> None:
        """
        Runs triage and TTP mapping on records that have no existing analysis.
        Skips records with no cve_id or no description since the LLM has nothing to work with.
        Skips records already present in ttp_mappings.
        Processes at most ANALYSIS_BATCH_LIMIT records per run.
        """
        analyzed = 0
        skipped = 0

        for record, threat_id in stored:
            if analyzed >= ANALYSIS_BATCH_LIMIT:
                logger.info("Analysis batch limit reached (%d). Remaining records deferred.", ANALYSIS_BATCH_LIMIT)
                break

            if not record.cve_id or not record.description:
                skipped += 1
                continue
            if self.store.is_analyzed(threat_id):
                skipped += 1
                continue

            try:
                triage_result = self.triage.triage(record)
                if triage_result:
                    self.store.save_triage_result(threat_id, triage_result)

                ttp_result = self.ttp_mapper.map(record)
                if ttp_result:
                    self.store.save_ttp_mappings(threat_id, ttp_result)

                analyzed += 1
            except Exception:
                logger.error("Analysis failed for %s", record.cve_id, exc_info=True)

        logger.info("Analysis complete: %d analyzed, %d skipped", analyzed, skipped)

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