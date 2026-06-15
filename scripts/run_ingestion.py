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
    with open("config/feeds.yaml", "r") as f:
        feed_config = yaml.safe_load(f)

    from src.ingestion.pipeline import IngestionPipeline
    from src.ingestion.store import ThreatStore
    from src.ingestion.embeddings import build_embedding_text, embed_text, store_embedding

    pipeline = IngestionPipeline(feed_config)
    store = ThreatStore()

    logger.info("Starting ingestion run")
    records = pipeline.run()
    logger.info("Pipeline returned %d records after deduplication", len(records))

    for record in records:
        threat_id = store.upsert_record(record)
        if threat_id:
            embedding = embed_text(build_embedding_text(record))
            store_embedding(threat_id, embedding)

    logger.info("Ingestion run complete")


if __name__ == "__main__":
    main()