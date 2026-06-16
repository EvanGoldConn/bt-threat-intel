import os
import logging

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src.ingestion.models import ThreatRecord, ExposureResult

logger = logging.getLogger(__name__)
console = Console()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
HTTP_TIMEOUT = 10


class Alerter:
    """
    Sends alerts for high-priority or confirmed-exposure findings.
    Outputs to Slack webhook and CLI via rich simultaneously.
    """

    def alert_exposure(self, record: ThreatRecord, exposure: ExposureResult) -> None:
        """Send an alert for a confirmed asset exposure."""
        self._cli_alert(record, exposure)
        if SLACK_WEBHOOK_URL:
            self._slack_alert(record, exposure)

    def _cli_alert(self, record: ThreatRecord, exposure: ExposureResult) -> None:
        """Print a formatted exposure alert to the terminal using rich."""
        severity = (record.severity or "unknown").upper()
        cvss = f"{record.cvss_score:.1f}" if record.cvss_score else "N/A"

        color = "red" if severity in ("CRITICAL", "HIGH") else "yellow"

        text = Text()
        text.append(f"CVE: {record.cve_id or 'N/A'}\n", style="bold white")
        text.append(f"Severity: {severity}  CVSS: {cvss}\n", style=f"bold {color}")
        text.append(f"Asset: {exposure.asset_name} {exposure.asset_version}\n", style="cyan")
        text.append(f"Rationale: {exposure.rationale}", style="white")

        console.print(Panel(
            text,
            title="[bold red]EXPOSURE CONFIRMED[/bold red]",
            border_style=color,
        ))

    def _slack_alert(self, record: ThreatRecord, exposure: ExposureResult) -> None:
        """
        POST a formatted message to the Slack webhook URL.
        Uses Slack Block Kit for structured formatting.
        Logs a warning on failure, does not raise.
        """
        severity = (record.severity or "unknown").upper()
        cvss = f"{record.cvss_score:.1f}" if record.cvss_score else "N/A"
        cve_id = record.cve_id or "N/A"

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "EXPOSURE CONFIRMED",
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*CVE:*\n{cve_id}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{severity} ({cvss})"},
                        {"type": "mrkdwn", "text": f"*Asset:*\n{exposure.asset_name} {exposure.asset_version}"},
                        {"type": "mrkdwn", "text": f"*Source:*\n{record.source}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Rationale:*\n{exposure.rationale}"
                    }
                },
            ]
        }

        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                resp = client.post(SLACK_WEBHOOK_URL, json=payload)
                if resp.status_code != 200:
                    logger.warning(
                        "Slack alert failed for %s: status %d, body %s",
                        cve_id,
                        resp.status_code,
                        resp.text,
                    )
        except httpx.HTTPError as e:
            logger.warning("Slack alert HTTP error for %s: %s", cve_id, e)

    def alert_high_severity(self, record: ThreatRecord, triage: dict) -> None:
        """
        Send an alert for a high or critical severity CVE without a confirmed exposure.
        Used to surface critical findings even when asset correlation is inconclusive.
        """
        severity = (record.severity or "unknown").upper()
        cvss = f"{record.cvss_score:.1f}" if record.cvss_score else "N/A"
        cve_id = record.cve_id or "N/A"
        priority = triage.get("priority", "unknown").upper()

        text = Text()
        text.append(f"CVE: {cve_id}\n", style="bold white")
        text.append(f"Severity: {severity}  CVSS: {cvss}  Priority: {priority}\n", style="bold red")
        text.append(f"Summary: {triage.get('summary', 'N/A')}", style="white")

        console.print(Panel(
            text,
            title="[bold yellow]HIGH SEVERITY ALERT[/bold yellow]",
            border_style="yellow",
        ))