import logging
import os
from typing import List, Optional

import httpx
import psycopg2

from src.ingestion.models import ThreatRecord
from src.ingestion.store import get_connection

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
HTTP_TIMEOUT = 30


def build_embedding_text(record: ThreatRecord) -> str:
    """
    Constructs the text string used to generate a record's embedding.
    Combines the fields most relevant to semantic search: CVE ID, severity,
    title, and description. Changing this function changes what the embedding
    represents for all future ingestion runs.
    """
    parts = []

    if record.cve_id:
        parts.append(record.cve_id)
    if record.severity:
        parts.append(record.severity)
    if record.title:
        parts.append(record.title)
    if record.description:
        parts.append(record.description)

    return " | ".join(parts)


def embed_text(text: str) -> Optional[List[float]]:
    """
    Generates a vector embedding for the given text using the local Ollama model.
    Returns a list of floats representing the embedding vector, or None on failure.
    """
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            response = client.post(
                f"{OLLAMA_BASE_URL}/api/embed",
                json={"model": EMBEDDING_MODEL, "input": text},
            )
            response.raise_for_status()
            embeddings = response.json().get("embeddings")
            return embeddings[0] if embeddings else None
    except httpx.HTTPError as e:
        logger.error("Ollama embedding request failed: %s", e)
        return None


def embed_batch(texts: List[str]) -> List[Optional[List[float]]]:
    """Embeds a list of texts and returns a list of embedding vectors."""
    return [embed_text(t) for t in texts]


def store_embedding(threat_id: int, embedding: List[float]) -> None:
    """
    Writes an embedding vector to the threat_embeddings table.
    The embedding column is type vector(768), matching nomic-embed-text output dimensions.
    """
    if embedding is None:
        logger.error("Received None embedding for threat_id %d, skipping store", threat_id)
        return

    sql = """
        INSERT INTO threat_embeddings (threat_id, embedding)
        VALUES (%s, %s)
        ON CONFLICT (threat_id) DO UPDATE SET embedding = EXCLUDED.embedding
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (threat_id, str(embedding)))
    except psycopg2.Error as e:
        logger.error("Failed to store embedding for threat_id %d: %s", threat_id, e)


def similarity_search(query_embedding: List[float], limit: int = 10) -> List[dict]:
    """
    Finds the most semantically similar threat records to a query embedding.
    Uses cosine distance via pgvector's <=> operator.
    Returns matched threat_records rows ordered by similarity ascending (lower is closer).
    """
    if query_embedding is None:
        logger.error("Received None query embedding, skipping similarity search")
        return []

    sql = """
        SELECT t.*, e.embedding <=> %s AS distance
        FROM threat_records t
        JOIN threat_embeddings e ON e.threat_id = t.id
        ORDER BY distance ASC
        LIMIT %s
    """
    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (str(query_embedding), limit))
                return [dict(row) for row in cur.fetchall()]
    except psycopg2.Error as e:
        logger.error("Similarity search failed: %s", e)
        return []