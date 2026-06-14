import logging
from typing import List

from src.analysis.client import AnalysisClient
from src.ingestion.embeddings import embed_text, similarity_search

logger = logging.getLogger(__name__)

CHAT_SYSTEM_PROMPT = """
You are a threat intelligence analyst assistant. Answer questions about CVEs,
vulnerabilities, and exposures using only the context provided. If the context
does not contain enough information to answer, say so clearly.
Be concise and technical. Reference specific CVE IDs when relevant.
"""

TOP_K_RESULTS = 5


class ChatPipeline:
    """
    RAG pipeline backing the analyst chat interface.
    Takes a natural language query, retrieves relevant threat records
    from the vector store, and passes them as context to the LLM.
    """

    def __init__(self):
        self.client = AnalysisClient()

    def query(self, user_message: str) -> str:
        """
        Handle a single analyst query. Returns the LLM response as a string.
        Steps: embed query -> similarity search -> build context -> LLM call
        """
        # TODO: embed user_message with embed_text()
        # Run similarity_search() to get top K relevant records
        # Format records as a context block
        # Call self.client.complete() with CHAT_SYSTEM_PROMPT and context + user_message
        raise NotImplementedError

    def _format_context(self, records: List[dict]) -> str:
        """Format retrieved threat records as a readable context block for the LLM prompt."""
        # TODO: build a plain text block listing CVE ID, severity, description, and published date
        # for each retrieved record
        raise NotImplementedError
