"""
Manual trigger for the asset correlator and alerting pipeline.
Run this after ingestion to check current records against the asset inventory.
Usage: python scripts/run_correlator.py
"""

import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main():
    from src.ingestion.store import ThreatStore
    from src.correlator.correlator import AssetCorrelator
    from src.analysis.playbook import PlaybookGenerator
    from src.alerting.alerter import Alerter

    store = ThreatStore()
    correlator = AssetCorrelator()
    playbook_gen = PlaybookGenerator()
    alerter = Alerter()

    records = store.get_recent_records(limit=100)
    logger.info(f"Correlating {len(records)} records against asset inventory")

    for row in records:
        # TODO: convert row dict back to ThreatRecord for correlator input
        # exposures = correlator.correlate(record, threat_id=row["id"])
        # for exposure in exposures:
        #     if exposure.is_exposed:
        #         playbook = playbook_gen.generate(record, exposure)
        #         alerter.alert_exposure(record, exposure)
        pass

    logger.info("Correlation run complete")


if __name__ == "__main__":
    main()
