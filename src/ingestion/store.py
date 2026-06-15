import json
import logging
import os
from typing import List, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from src.ingestion.models import ThreatRecord

logger = logging.getLogger(__name__)


def get_connection():
    """Return a psycopg2 connection using environment variables."""
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
    )


class ThreatStore:
    """
    Handles reading and writing threat records to PostgreSQL.
    Separate from the ingestion logic so the storage layer can be
    swapped or extended without touching feed code.
    """

    def upsert_record(self, record: ThreatRecord) -> Optional[int]:
        """
        Inserts a ThreatRecord or updates the existing row if the cve_id already exists.
        Fields with no equivalent in the source feed are stored as NULL.
        Returns the database row id on success, None on failure.
        """
        sql = """
            INSERT INTO threat_records (
                cve_id, source, title, description,
                cvss_score, cvss_vector, severity,
                published_at, modified_at,
                reference_urls, raw_data
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s,
                %s, %s
            )
            ON CONFLICT (cve_id) DO UPDATE SET
                source        = EXCLUDED.source,
                title         = EXCLUDED.title,
                description   = EXCLUDED.description,
                cvss_score    = EXCLUDED.cvss_score,
                cvss_vector   = EXCLUDED.cvss_vector,
                severity      = EXCLUDED.severity,
                published_at  = EXCLUDED.published_at,
                modified_at   = EXCLUDED.modified_at,
                reference_urls = EXCLUDED.reference_urls,
                raw_data      = EXCLUDED.raw_data
            RETURNING id
        """ #ON CONFLICT, references values that were attempted to be inserted; excluded.cvss_score = cvss score value that JUST came in
        values = (
            record.cve_id,
            record.source,
            record.title,
            record.description,
            record.cvss_score,
            record.cvss_vector,
            record.severity,
            record.published_at,
            record.modified_at,
            Json(record.reference_urls), #psycopg2 wraps lists/dicts to serialize them correctly for jsonb columns
            Json(record.raw_data),
        )

        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, values)
                    row = cur.fetchone()
                    return row[0] if row else None
        except psycopg2.Error as e:
            logger.error("Failed to upsert record %s: %s", record.cve_id, e)
            return None

    def get_record_by_cve(self, cve_id: str) -> Optional[dict]:
        """Fetches a single threat record by CVE ID. Returns None if not found."""
        sql = "SELECT * FROM threat_records WHERE cve_id = %s"

        try:
            with get_connection() as conn: 
                with conn.cursor(cursor_factory=RealDictCursor) as cur: #realdictcursor returns rows as dicts keyed by column instead of tuples
                    cur.execute(sql, (cve_id,))
                    row = cur.fetchone()
                    return dict(row) if row else None
        except psycopg2.Error as e:
            logger.error("Failed to fetch record for CVE %s: %s", cve_id, e)
            return None

    def get_recent_records(self, limit: int = 50) -> List[dict]:
        """Fetches the most recently ingested records ordered by created_at descending."""
        sql = "SELECT * FROM threat_records ORDER BY created_at DESC LIMIT %s"

        try:
            with get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(sql, (limit,))
                    return [dict(row) for row in cur.fetchall()]
        except psycopg2.Error as e:
            logger.error("Failed to fetch recent records: %s", e)
            return []

    def record_exists(self, cve_id: str) -> bool:
        """Returns True if the given CVE ID exists in the store."""
        sql = "SELECT 1 FROM threat_records WHERE cve_id = %s"

        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (cve_id,))
                    return cur.fetchone() is not None
        except psycopg2.Error as e:
            logger.error("Failed to check existence for CVE %s: %s", cve_id, e)
            return False