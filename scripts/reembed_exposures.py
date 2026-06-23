"""
Re-embeds all confirmed exposure records with enriched embedding text.
Enriched text includes a CONFIRMED EXPOSURE marker, the affected asset name,
and the CISA KEV ransomware signal if present.

Run this after any correlator run that produces new confirmed exposures,
and after any change to build_embedding_text() in embeddings.py.

Usage: python scripts/reembed_exposures.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

from src.ingestion.store import ThreatStore
from src.ingestion.embeddings import build_embedding_text, embed_text, store_embedding
from src.ingestion.models import ThreatRecord


def row_to_threat_record(row: dict) -> ThreatRecord:
    """Convert a raw database row dict to a ThreatRecord."""
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


def main():
    store = ThreatStore()
    exposures = store.get_confirmed_exposures()

    if not exposures:
        logger.info("No confirmed exposures found. Run the correlator first.")
        return

    logger.info("Re-embedding %d confirmed exposure records", len(exposures))

    success = 0
    failed = 0

    for row in exposures:
        threat_id = row.get("id")
        asset_name = row.get("asset_name")
        cve_id = row.get("cve_id") or "unknown"

        if not threat_id:
            logger.warning("Row missing id field, skipping")
            failed += 1
            continue

        record = row_to_threat_record(row)
        enriched_text = build_embedding_text(
            record,
            confirmed_exposure=True,
            asset_name=asset_name,
        )

        logger.debug("Embedding %s (asset: %s)", cve_id, asset_name)
        vector = embed_text(enriched_text)

        if vector is None:
            logger.error("Embedding failed for threat_id %d (%s)", threat_id, cve_id)
            failed += 1
            continue

        store_embedding(threat_id, vector)
        success += 1
        logger.info("Re-embedded threat_id %d: %s -> %s", threat_id, cve_id, asset_name)

    logger.info("Re-embedding complete: %d updated, %d failed", success, failed)


if __name__ == "__main__":
    main()
