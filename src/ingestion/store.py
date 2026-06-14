import os
import logging
from typing import List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

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
        Insert a new ThreatRecord or update it if the CVE ID already exists.
        Returns the database row ID.
        """
        # TODO: implement upsert using INSERT ... ON CONFLICT (cve_id) DO UPDATE
        raise NotImplementedError

    def get_record_by_cve(self, cve_id: str) -> Optional[dict]:
        """Fetch a single threat record by CVE ID."""
        # TODO: SELECT from threat_records where cve_id = %s
        raise NotImplementedError

    def get_recent_records(self, limit: int = 50) -> List[dict]:
        """Fetch the most recently ingested records."""
        # TODO: SELECT from threat_records ORDER BY created_at DESC LIMIT %s
        raise NotImplementedError

    def record_exists(self, cve_id: str) -> bool:
        """Check if a CVE ID is already in the store."""
        # TODO: SELECT 1 from threat_records where cve_id = %s
        raise NotImplementedError
