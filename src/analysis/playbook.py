import logging
from typing import Optional


from src.ingestion.models import ThreatRecord, IRPlaybook, ExposureResult
from src.analysis.client import get_analysis_client

logger = logging.getLogger(__name__)

PLAYBOOK_SYSTEM_PROMPT = """
You are a security engineer writing incident response procedures.
Given a CVE and confirmed asset exposure, generate a concise IR playbook.
Return a JSON object with:
- priority: "critical" | "high" | "medium" | "low"
- steps: list of strings, each an actionable step in order
Keep steps specific and technical. Assume the reader is a competent engineer.
Limit to 6 steps maximum.
"""


class PlaybookGenerator:
    """
    Generates structured IR playbooks for confirmed asset exposures.
    Output is scoped to basic remediation and detection steps for v1.
    """

    def __init__(self):
        self.client = get_analysis_client()

    def generate(self, record: ThreatRecord, exposure: ExposureResult) -> Optional[IRPlaybook]:
        """
        Generate an IR playbook for a confirmed exposure.
        Returns None if generation fails.
        """
        # TODO: build user prompt from record (cve_id, description, severity)
        # and exposure (asset_name, asset_version, rationale)
        # Call self.client.complete_json() and parse into an IRPlaybook
        raise NotImplementedError
