import json
import logging
import os
import unicodedata
from typing import List, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from src.ingestion.models import ThreatRecord

logger = logging.getLogger(__name__)

MAX_FIELD_LENGTH = 8000


def get_connection():
    """Return a psycopg2 connection using environment variables."""
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
    )


def _sanitize_text(value: Optional[str]) -> Optional[str]:
    """
    Strips null bytes and non-printable control characters from a string.
    Truncates to MAX_FIELD_LENGTH characters.
    Returns None if value is None.
    """
    if value is None:
        return None
    cleaned = "".join(
        ch for ch in value
        if ch == "\n" or ch == "\t" or not unicodedata.category(ch).startswith("C")
    )
    return cleaned[:MAX_FIELD_LENGTH]


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
        """
        values = (
            record.cve_id,
            record.source,
            _sanitize_text(record.title),
            _sanitize_text(record.description),
            record.cvss_score,
            record.cvss_vector,
            record.severity,
            record.published_at,
            record.modified_at,
            Json(record.reference_urls),
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
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
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

    def get_records_for_correlation(self, limit: int = 200) -> List[dict]:
        """
        Fetches records that have both a cve_id and description.
        Filters to critical and high severity only.
        Ordered by cvss_score descending so highest-risk records correlate first.
        """
        sql = """
            SELECT * FROM threat_records
            WHERE cve_id IS NOT NULL
            AND description IS NOT NULL
            AND severity IN ('critical', 'high')
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT %s
        """
        try:
            with get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(sql, (limit,))
                    return [dict(row) for row in cur.fetchall()]
        except psycopg2.Error as e:
            logger.error("Failed to fetch records for correlation: %s", e)
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

    def is_analyzed(self, threat_id: int) -> bool:
        """Returns True if TTP mappings already exist for the given threat_id."""
        sql = "SELECT 1 FROM ttp_mappings WHERE threat_id = %s LIMIT 1"

        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (threat_id,))
                    return cur.fetchone() is not None
        except psycopg2.Error as e:
            logger.error("Failed to check analysis status for threat_id %s: %s", threat_id, e)
            return False

    def embedding_exists(self, threat_id: int) -> bool:
        """Returns True if an embedding already exists for the given threat_id."""
        sql = "SELECT 1 FROM threat_embeddings WHERE threat_id = %s"

        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (threat_id,))
                    return cur.fetchone() is not None
        except psycopg2.Error as e:
            logger.error("Failed to check embedding existence for threat_id %s: %s", threat_id, e)
            return False

    def save_triage_result(self, threat_id: int, triage: dict) -> bool:
        """
        Writes triage result fields into raw_data as triage_* prefixed keys via jsonb_set().
        Keys: triage_exploitability, triage_attack_vector, triage_priority,
        triage_summary, triage_rationale.
        Returns True on success, False on failure.
        """
        sql = """
            UPDATE threat_records SET
                raw_data = jsonb_set(
                    jsonb_set(
                        jsonb_set(
                            jsonb_set(
                                jsonb_set(
                                    COALESCE(raw_data, '{}'),
                                    '{triage_exploitability}', %s::jsonb
                                ),
                                '{triage_attack_vector}', %s::jsonb
                            ),
                            '{triage_priority}', %s::jsonb
                        ),
                        '{triage_summary}', %s::jsonb
                    ),
                    '{triage_rationale}', %s::jsonb
                )
            WHERE id = %s
        """
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (
                        json.dumps(triage.get("exploitability")),
                        json.dumps(triage.get("attack_vector")),
                        json.dumps(triage.get("priority")),
                        json.dumps(triage.get("summary")),
                        json.dumps(triage.get("rationale")),
                        threat_id,
                    ))
                    return True
        except psycopg2.Error as e:
            logger.error("Failed to save triage result for threat_id %s: %s", threat_id, e)
            return False

    def save_ttp_mappings(self, threat_id: int, ttps: List[dict]) -> bool:
        """
        Inserts one row per TTP into ttp_mappings.
        Uses ON CONFLICT DO NOTHING as safety net against duplicate inserts.
        Returns True on success, False on failure.
        """
        sql = """
            INSERT INTO ttp_mappings (threat_id, tactic, technique_id, technique_name, confidence)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    for ttp in ttps:
                        cur.execute(sql, (
                            threat_id,
                            ttp.get("tactic"),
                            ttp.get("technique_id"),
                            ttp.get("technique_name"),
                            ttp.get("confidence"),
                        ))
                    return True
        except psycopg2.Error as e:
            logger.error("Failed to save TTP mappings for threat_id %s: %s", threat_id, e)
            return False