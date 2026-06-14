import json
import logging
from typing import List


from src.ingestion.models import ThreatRecord
from src.analysis.client import get_analysis_client

logger = logging.getLogger(__name__)

TTP_SYSTEM_PROMPT = """
You are a threat intelligence analyst with expertise in MITRE ATT&CK.
Given a CVE description, identify the most relevant ATT&CK tactics and techniques.
Return a JSON array of objects, each with:
- tactic: the ATT&CK tactic name (e.g. "Initial Access")
- technique_id: the ATT&CK technique ID (e.g. "T1190")
- technique_name: the technique name (e.g. "Exploit Public-Facing Application")
- confidence: "high" | "medium" | "low"
Limit to the 3 most relevant techniques.
"""


class TtpMapper:
    """
    Maps CVE descriptions to MITRE ATT&CK tactics and techniques using the LLM.
    Helps place each vulnerability in the context of an attack kill chain.
    """

    def __init__(self):
        self.client = get_analysis_client()

    def map(self, record: ThreatRecord) -> List[dict]:
        """
        Return a list of TTP mappings for a given ThreatRecord.
        Each entry contains tactic, technique_id, technique_name, and confidence.
        """
        # TODO: build user prompt from record description and cve_id
        # Call self.client.complete_json() and parse the JSON array response
        # Return empty list on failure rather than raising
        raise NotImplementedError
