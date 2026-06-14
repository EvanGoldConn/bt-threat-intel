import json
import logging
from typing import Optional


from src.ingestion.models import ThreatRecord
from src.analysis.client import get_analysis_client

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """
You are a senior security analyst. Given a CVE description and metadata, assess the threat.
Return a JSON object with the following fields:
- exploitability: "confirmed" | "probable" | "theoretical" | "unknown"
- attack_vector: "network" | "adjacent" | "local" | "physical" | "unknown"
- priority: "critical" | "high" | "medium" | "low"
- summary: one sentence plain-language description of the risk
- rationale: 2-3 sentences explaining the priority assessment
"""


class CveTriage:
    """
    Uses the LLM to enrich raw CVE data with exploitability and priority assessments
    beyond what the CVSS score alone provides.
    """

    def __init__(self):
        self.client = get_analysis_client()

    def triage(self, record: ThreatRecord) -> Optional[dict]:
        """
        Run LLM triage on a ThreatRecord. Returns a dict with priority,
        exploitability, and a plain-language summary.
        """
        # TODO: build user prompt from record fields (cve_id, description, cvss_score, references)
        # Call self.client.complete_json() and parse the response
        # Handle JSON parse errors gracefully, return None on failure
        raise NotImplementedError
