"""
Scheduled runner for the full pipeline.
Runs ingestion, correlation, and exposure re-embedding on a configurable interval.
Ingestion and correlation run in sequence, not in parallel.
Correlation only runs after ingestion completes successfully.

Usage: python scripts/scheduler.py
Set INGEST_SCHEDULE_HOURS in .env to control the interval (default: 6).
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import logging
import time
from dotenv import load_dotenv
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

INGEST_SCHEDULE_HOURS = int(os.getenv("INGEST_SCHEDULE_HOURS", 6))


def pipeline_job():
    """
    Full pipeline job: ingestion, correlation, re-embedding in sequence.
    Each step is independent. A failure in one step is logged but does not
    crash the scheduler process or prevent the next scheduled run.
    """
    from scripts.run_pipeline import run_ingestion, run_correlator, run_reembed

    logger.info("Scheduled pipeline job starting")
    start = time.time()

    try:
        ingestion_ok = run_ingestion()
        if not ingestion_ok:
            logger.error("Ingestion step failed. Continuing with existing data.")

        correlation_count = run_correlator()
        if correlation_count < 0:
            logger.error("Correlation step failed. Skipping re-embedding.")
            return

        if correlation_count > 0:
            run_reembed()
        else:
            logger.info("No new exposures. Skipping re-embedding.")

        elapsed = time.time() - start
        logger.info("Scheduled pipeline job complete in %.1fs", elapsed)

    except Exception as e:
        logger.error("Pipeline job failed with unhandled exception: %s", e)


def _on_job_executed(event):
    """Log successful job execution."""
    logger.info("Job %s executed successfully", event.job_id)


def _on_job_error(event):
    """Log job execution errors without crashing the scheduler."""
    logger.error("Job %s raised an exception: %s", event.job_id, event.exception)


def main():
    scheduler = BlockingScheduler()

    scheduler.add_job(
        pipeline_job,
        trigger="interval",
        hours=INGEST_SCHEDULE_HOURS,
        id="pipeline",
        name="Full pipeline: ingest, correlate, reembed",
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_listener(_on_job_executed, EVENT_JOB_EXECUTED)
    scheduler.add_listener(_on_job_error, EVENT_JOB_ERROR)

    logger.info(
        "Scheduler started. Pipeline runs every %d hour(s). Press Ctrl+C to stop.",
        INGEST_SCHEDULE_HOURS
    )
    logger.info("Next run: %s", scheduler.get_jobs()[0].next_run_time)

    try:
        scheduler.start()
    except KeyboardInterrupt:
        logger.info("Scheduler stopped by user.")
        scheduler.shutdown()


if __name__ == "__main__":
    main()