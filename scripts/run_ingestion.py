"""
Manual trigger for the ingestion pipeline.
Run this to populate the database from all enabled feeds.
Usage: python scripts/run_ingestion.py
"""
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import yaml
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main():
    from src.ingestion.pipeline import IngestionPipeline

    with open("config/feeds.yaml", "r") as f:
        feed_config = yaml.safe_load(f)

    logger.info("Starting ingestion run")
    pipeline = IngestionPipeline(feed_config)
    pipeline.run()
    logger.info("Ingestion run complete")


if __name__ == "__main__":
    main()