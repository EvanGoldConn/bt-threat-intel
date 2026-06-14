import os
import logging
from typing import List

import httpx

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")


def embed_text(text: str) -> List[float]:
    """
    Generate a vector embedding for the given text using the local Ollama model.
    Returns a list of floats representing the embedding vector.
    """
    # TODO: POST to {OLLAMA_BASE_URL}/api/embeddings with model and prompt fields
    # Handle connection errors gracefully with logging
    raise NotImplementedError


def embed_batch(texts: List[str]) -> List[List[float]]:
    """Embed a list of texts, returning a list of embedding vectors."""
    return [embed_text(t) for t in texts]


def store_embedding(threat_id: int, embedding: List[float]) -> None:
    """Write an embedding vector to the threat_embeddings table."""
    # TODO: INSERT into threat_embeddings (threat_id, embedding) VALUES (%s, %s)
    raise NotImplementedError


def similarity_search(query_embedding: List[float], limit: int = 10) -> List[dict]:
    """
    Find the most semantically similar threat records to a query embedding.
    Uses cosine similarity via pgvector's <=> operator.
    """
    # TODO: SELECT t.* FROM threat_records t
    #       JOIN threat_embeddings e ON e.threat_id = t.id
    #       ORDER BY e.embedding <=> %s LIMIT %s
    raise NotImplementedError
