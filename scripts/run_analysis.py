




import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import logging
from dotenv import load_dotenv
load_dotenv()

import psycopg2
from datetime import datetime, timezone

from src.ingestion.models import ThreatRecord, ExposureResult
from src.analysis.triage import CveTriage
from src.analysis.ttp_mapper import TtpMapper
from src.analysis.playbook import PlaybookGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def fetch_highest_cvss_record() -> ThreatRecord:
    """
    Fetch the threat_record with the highest CVSS score from PostgreSQL.
    Returns a ThreatRecord instance.
    """
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", 5432),
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
    )
    cur = conn.cursor()
    cur.execute("""
        SELECT cve_id, source, title, description, cvss_score, cvss_vector,
               severity, published_at, modified_at, reference_urls, raw_data
        FROM threat_records
        WHERE cvss_score IS NOT NULL
        ORDER BY cvss_score DESC
        LIMIT 1
    """)
    row = cur.fetchone()
    cur.close()
    conn.close()

    return ThreatRecord(
        cve_id=row[0],
        source=row[1],
        title=row[2],
        description=row[3],
        cvss_score=row[4],
        cvss_vector=row[5],
        severity=row[6],
        published_at=row[7],
        modified_at=row[8],
        reference_urls=row[9] if row[9] else [],
        raw_data=row[10] if row[10] else {},
    )


def mock_exposure(record: ThreatRecord) -> ExposureResult:
    """
    Build a mock ExposureResult for testing playbook generation.
    No real correlator output exists yet.
    """
    return ExposureResult(
        threat_id=1,
        asset_name="test-asset",
        asset_version="1.0.0",
        is_exposed=True,
        rationale=f"Mock exposure for testing playbook generation against {record.cve_id}.",
    )


def main():
    logger.info("Fetching highest CVSS record from threat_records")
    record = fetch_highest_cvss_record()
    logger.info("Testing against %s (CVSS: %s, severity: %s)", record.cve_id, record.cvss_score, record.severity)
    logger.info("Description: %s", record.description)

    print("\n--- TRIAGE ---")
    triage = CveTriage()
    triage_result = triage.triage(record)
    print(json.dumps(triage_result, indent=2))

    print("\n--- TTP MAPPING ---")
    mapper = TtpMapper()
    ttp_result = mapper.map(record)
    print(json.dumps(ttp_result, indent=2))

    print("\n--- IR PLAYBOOK ---")
    generator = PlaybookGenerator()
    exposure = mock_exposure(record)
    playbook = generator.generate(record, exposure)
    if playbook:
        print(json.dumps({
            "cve_id": playbook.cve_id,
            "priority": playbook.priority,
            "steps": playbook.steps,
            "generated_at": playbook.generated_at.isoformat(),
        }, indent=2))
    else:
        print("Playbook generation failed.")


if __name__ == "__main__":
    main()