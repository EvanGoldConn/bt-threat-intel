import os
import logging

import httpx
from rich.console import Console

from src.ingestion.models import ThreatRecord, ExposureResult

logger = logging.getLogger(__name__)
console = Console()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


class Alerter:
    """
    Sends alerts for high-priority or confirmed-exposure findings.
    Outputs to Slack webhook and CLI (via rich) simultaneously.
    """

    def alert_exposure(self, record: ThreatRecord, exposure: ExposureResult) -> None:
        """Send an alert for a confirmed asset exposure."""
        self._cli_alert(record, exposure)
        if SLACK_WEBHOOK_URL:
            self._slack_alert(record, exposure)

    def _cli_alert(self, record: ThreatRecord, exposure: ExposureResult) -> None:
        """Print a formatted exposure alert to the terminal."""
        # TODO: use rich to print a styled alert with CVE ID, severity, asset name, and rationale
        raise NotImplementedError

    def _slack_alert(self, record: ThreatRecord, exposure: ExposureResult) -> None:
        """
        POST a formatted message to the Slack webhook URL.
        Uses Slack Block Kit for structured formatting.
        Docs: https://api.slack.com/messaging/webhooks
        """
        # TODO: build a Slack Block Kit payload with CVE ID, severity, asset, and rationale
        # POST to SLACK_WEBHOOK_URL with httpx
        # Log a warning on failure, do not raise (alerting should not crash the pipeline)
        raise NotImplementedError

    def alert_high_severity(self, record: ThreatRecord, triage: dict) -> None:
        """Send an alert for a high/critical severity CVE even without a confirmed exposure."""
        # TODO: implement similar to alert_exposure but scoped to severity threshold
        raise NotImplementedError
