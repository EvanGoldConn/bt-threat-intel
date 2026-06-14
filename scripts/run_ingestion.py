"""
Manual trigger for the ingestion pipeline.
Run this to populate the database from all enabled feeds.
Usage: python scripts/run_ingestion.py
"""

import logging
import yaml
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main():
    with open("config/feeds.yaml", "r") as f:
        feed_config = yaml.safe_load(f)["feeds"]

    from src.ingestion.pipeline import IngestionPipeline
    from src.ingestion.store import ThreatStore
    from src.ingestion.embeddings import embed_text, store_embedding

    pipeline = IngestionPipeline(feed_config)
    store = ThreatStore()

    logger.info("Starting ingestion run")
    records = pipeline.run()
    logger.info(f"Pipeline returned {len(records)} records after deduplication")

    for record in records:
        threat_id = store.upsert_record(record)
        if threat_id:
            text_to_embed = f"{record.cve_id or ''} {record.title or ''} {record.description or ''}"
            embedding = embed_text(text_to_embed)
            store_embedding(threat_id, embedding)

    logger.info("Ingestion run complete")


if __name__ == "__main__":
    main()
