"""
Manual trigger for the asset correlator.
Fetches recent threat records, correlates against stack.yaml,
generates IR playbooks for confirmed exposures, and fires alerts.
Usage: python scripts/run_correlator.py
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

CORRELATOR_LIMIT = 500 #caps how many records to correlate per run


def row_to_threat_record(row: dict):
    """Convert a raw database row dict to a ThreatRecord."""
    from src.ingestion.models import ThreatRecord
    return ThreatRecord(
        cve_id=row.get("cve_id"),
        source=row["source"],
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
    from src.ingestion.store import ThreatStore
    from src.correlator.correlator import AssetCorrelator
    from src.analysis.playbook import PlaybookGenerator
    from src.alerting.alerter import Alerter

    store = ThreatStore()
    correlator = AssetCorrelator()
    playbook_gen = PlaybookGenerator()
    alerter = Alerter()

    rows = store.get_records_for_correlation(limit=CORRELATOR_LIMIT)
    logger.info("Correlating %d records against asset inventory", len(rows))

    total_exposures = 0

    for row in rows:
        threat_id = row["id"]
        record = row_to_threat_record(row)

        if not record.description:
            continue

        exposures = correlator.correlate(record, threat_id)

        for exposure in exposures:
            if not exposure.is_exposed:
                continue

            total_exposures += 1
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
                    record.cve_id,
                    playbook.priority,
                    len(playbook.steps),
                )

            alerter.alert_exposure(record, exposure)

    logger.info("Correlation complete. Confirmed exposures: %d", total_exposures)


if __name__ == "__main__":
    main()