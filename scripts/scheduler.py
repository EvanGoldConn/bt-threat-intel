"""
Scheduled runner for the ingestion and correlator pipelines.
Runs ingestion on the interval defined by INGEST_SCHEDULE_HOURS in .env.
Usage: python scripts/scheduler.py
"""

import logging
import yaml
from dotenv import load_dotenv
from apscheduler.schedulers.blocking import BlockingScheduler

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

INGEST_SCHEDULE_HOURS = int(__import__("os").getenv("INGEST_SCHEDULE_HOURS", 6))


def ingestion_job():
    # TODO: import and call run_ingestion main() here
    logger.info("Ingestion job triggered")


def correlator_job():
    # TODO: import and call run_correlator main() here
    logger.info("Correlator job triggered")


if __name__ == "__main__":
    scheduler = BlockingScheduler()
    scheduler.add_job(ingestion_job, "interval", hours=INGEST_SCHEDULE_HOURS)
    scheduler.add_job(correlator_job, "interval", hours=INGEST_SCHEDULE_HOURS)
    logger.info(f"Scheduler started. Ingestion runs every {INGEST_SCHEDULE_HOURS} hours.")
    scheduler.start()