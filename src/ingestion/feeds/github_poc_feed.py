import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import httpx

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
HTTP_TIMEOUT = 30


class GithubPocFeed(BaseFeed):
    """
    Monitors GitHub for newly published PoC exploit repositories.
    Searches for repos matching CVE identifiers created within the lookback window.
    A matching GitHub repo is a strong signal that a CVE has a public working exploit.
    """

    def fetch(self) -> List[ThreatRecord]:
        """
        Searches GitHub for PoC repositories created within the configured lookback window.
        Paginates until max_results is reached or no further results are available.
        GitHub caps search results at 1000 total regardless of total_count.
        Unauthenticated requests are limited to 60/ hour.
        """
        lookback_days = self.config.get("lookback_days", 3)
        max_results = self.config.get("max_results", 30) #top 30 highest signals first
        search_query = self.config.get("search_query", "CVE poc exploit")

        since_date = (
            datetime.now(timezone.utc) - timedelta(days=lookback_days)
        ).strftime("%Y-%m-%d")

        # Appending created: to the query restricts results to repos created
        # within the lookback window, filtering out older repos that happen
        # to match the search terms.
        query = f"{search_query} created:>{since_date}"

        headers = {"Accept": "application/vnd.github+json"}
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        records: List[ThreatRecord] = []
        page = 1
        per_page = min(100, max_results)

        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            while len(records) < max_results:
                params = {
                    "q": query,
                    "sort": "stars", #first results are the most starred repos
                    "order": "desc", 
                    "per_page": per_page,
                    "page": page,
                }

                try:
                    response = client.get(GITHUB_SEARCH_URL, headers=headers, params=params)
                    response.raise_for_status()
                except httpx.HTTPError as e:
                    logger.error("GitHub search request failed on page %d: %s", page, e)
                    break

                data = response.json()
                items = data.get("items", [])

                if not items:
                    break

                for item in items:
                    if len(records) >= max_results:
                        break
                    try:
                        records.append(self.normalize(item))
                    except Exception as e:
                        logger.error("Failed to normalize GitHub repo %s: %s", item.get("full_name", "unknown"), e)

                page += 1

        logger.info("GitHub PoC feed fetched %d records", len(records))
        return records

    def normalize(self, raw: dict) -> ThreatRecord:
        """
        Maps a GitHub repository to a ThreatRecord.
        Attempts to extract a CVE ID from the repo name and description via regex.
        Repos without a detectable CVE ID are ingested with cve_id=None.

        stargazers_count is stored in raw_data as a noise-reduction signal.
        Repos with higher star counts are more likely to contain functional PoC code
        that has been validated by the security community. Repos with zero stars are
        more likely to be incomplete, untested, or unrelated to the search terms.
        The analysis layer can use stargazers_count during triage to weight
        exploitability assessments and filter low-confidence results.
        """
        name = raw.get("full_name", "")
        description = raw.get("description") or ""

        # Check repo name first, then description for a CVE ID.
        # Repo names like CVE-2024-12345-RCE-PoC are the strongest signal.
        cve_match = CVE_PATTERN.search(name) or CVE_PATTERN.search(description)
        cve_id: Optional[str] = cve_match.group(0).upper() if cve_match else None

        published_at = None
        if raw.get("created_at"):
            published_at = datetime.fromisoformat(
                raw["created_at"].replace("Z", "+00:00")
            )

        return ThreatRecord(
            cve_id=cve_id,
            source="github_poc",
            title=name,
            description=description or None,
            cvss_score=None,
            cvss_vector=None,
            severity=None,
            published_at=published_at,
            modified_at=None,
            reference_urls=[raw["html_url"]] if raw.get("html_url") else [],
            raw_data={
                "repo_name": name,
                "stargazers_count": raw.get("stargazers_count", 0),
                "forks_count": raw.get("forks_count", 0),
                "language": raw.get("language"),
                "topics": raw.get("topics", []),
            },
        )