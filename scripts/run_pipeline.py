"""
Full pipeline runner. Runs ingestion, correlation, and exposure re-embedding
in sequence. Use this to bring the system fully up to date in one command.

Usage: python scripts/run_pipeline.py

Steps:
    1. Ingestion: pulls from all enabled feeds, stores and embeds new records
    2. Correlation: runs unprocessed records against stack.yaml, writes confirmed exposures
    3. Re-embedding: re-embeds confirmed exposure records with enriched text
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import logging
import time
import yaml
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def run_ingestion():
    """Run the ingestion pipeline. Returns True on success, False on failure."""
    from src.ingestion.pipeline import IngestionPipeline

    logger.info("=== STEP 1/3: INGESTION ===")
    start = time.time()

    try:
        with open("config/feeds.yaml", "r") as f:
            feed_config = yaml.safe_load(f)

        pipeline = IngestionPipeline(feed_config)
        records = pipeline.run()
        elapsed = time.time() - start
        logger.info("Ingestion complete: %d records in %.1fs", len(records), elapsed)
        return True
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        return False


def run_correlator():
    """
    Run the correlator against all unprocessed threat records.
    Returns count of confirmed exposures found, or -1 on failure.
    """
    from src.ingestion.store import ThreatStore
    from src.correlator.correlator import AssetCorrelator
    from src.analysis.playbook import PlaybookGenerator
    from src.alerting.alerter import Alerter
    from src.ingestion.models import ThreatRecord

    logger.info("=== STEP 2/3: CORRELATION ===")
    start = time.time()

    def row_to_threat_record(row: dict) -> ThreatRecord:
        return ThreatRecord(
            cve_id=row.get("cve_id"),
            source=row.get("source") or "",
            title=row.get("title"),
            description=row.get("description"),
            cvss_score=row.get("cvss_score"),
            cvss_vector=row.get("cvss_vector"),
            severity=row.get("severity"),
            published_at=row.get("published_at"),
            modified_at=row.get("modified_at"),
            reference_urls=row.get("reference_urls") or [],
            raw_data=row.get("raw_data") or {},
        )

    try:
        store = ThreatStore()
        correlator = AssetCorrelator()
        playbook_gen = PlaybookGenerator()
        alerter = Alerter()

        rows = store.get_uncorrelated_records()
        logger.info("Correlating %d unprocessed records", len(rows))

        total_exposures = 0

        for row in rows:
            threat_id = row["id"]
            record = row_to_threat_record(row)

            if not record.description:
                store.mark_correlated(threat_id)
                continue

            exposures = correlator.correlate(record, threat_id)

            for exposure in exposures:
                if not exposure.is_exposed:
                    continue

                total_exposures += 1
                store.save_exposure(exposure)
                logger.info(
                    "Exposure confirmed: %s affects %s %s",
                    record.cve_id,
                    exposure.asset_name,
                    exposure.asset_version,
                )

                playbook = playbook_gen.generate(record, exposure)
                if playbook:
                    logger.info(
                        "Playbook generated for %s: priority=%s, steps=%d",
                        record.cve_id, playbook.priority, len(playbook.steps),
                    )

                alerter.alert_exposure(record, exposure)

            store.mark_correlated(threat_id)

        elapsed = time.time() - start
        logger.info(
            "Correlation complete: %d exposures confirmed in %.1fs",
            total_exposures, elapsed
        )
        return total_exposures

    except Exception as e:
        logger.error("Correlation failed: %s", e)
        return -1


def run_reembed():
    """
    Re-embed all confirmed exposure records with enriched text.
    Returns True on success, False on failure.
    """
    from src.ingestion.store import ThreatStore
    from src.ingestion.embeddings import build_embedding_text, embed_text, store_embedding
    from src.ingestion.models import ThreatRecord

    logger.info("=== STEP 3/3: RE-EMBEDDING EXPOSURES ===")
    start = time.time()

    def row_to_threat_record(row: dict) -> ThreatRecord:
        return ThreatRecord(
            cve_id=row.get("cve_id"),
            source=row.get("source") or "",
            title=row.get("title"),
            description=row.get("description"),
            cvss_score=row.get("cvss_score"),
            cvss_vector=row.get("cvss_vector"),
            severity=row.get("severity"),
            published_at=row.get("published_at"),
            modified_at=row.get("modified_at"),
            reference_urls=row.get("reference_urls") or [],
            raw_data=row.get("raw_data") or {},
        )

    try:
        store = ThreatStore()
        exposures = store.get_confirmed_exposures()

        if not exposures:
            logger.info("No confirmed exposures to re-embed")
            return True

        success = 0
        failed = 0

        for row in exposures:
            threat_id = row.get("id")
            asset_name = row.get("asset_name")
            cve_id = row.get("cve_id") or "unknown"

            if not threat_id:
                failed += 1
                continue

            record = row_to_threat_record(row)
            enriched_text = build_embedding_text(
                record,
                confirmed_exposure=True,
                asset_name=asset_name,
            )

            vector = embed_text(enriched_text)
            if vector is None:
                logger.error("Embedding failed for threat_id %d (%s)", threat_id, cve_id)
                failed += 1
                continue

            store_embedding(threat_id, vector)
            success += 1

        elapsed = time.time() - start
        logger.info(
            "Re-embedding complete: %d updated, %d failed in %.1fs",
            success, failed, elapsed
        )
        return failed == 0

    except Exception as e:
        logger.error("Re-embedding failed: %s", e)
        return False


def main():
    logger.info("Starting full pipeline run")
    overall_start = time.time()

    ingestion_ok = run_ingestion()
    if not ingestion_ok:
        logger.error("Ingestion failed. Continuing to correlation with existing data.")

    correlation_count = run_correlator()
    if correlation_count < 0:
        logger.error("Correlation failed. Skipping re-embedding.")
        return

    if correlation_count > 0:
        run_reembed()
    else:
        logger.info("No new exposures found. Skipping re-embedding.")

    elapsed = time.time() - overall_start
    logger.info("Full pipeline complete in %.1fs", elapsed)


if __name__ == "__main__":
    main()
