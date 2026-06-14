import httpx
from typing import List

from src.ingestion.base_feed import BaseFeed
from src.ingestion.models import ThreatRecord

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


class GithubPocFeed(BaseFeed):
    """
    Monitors GitHub for newly published PoC exploit repositories.
    Searches for repos matching CVE identifiers created within the lookback window.
    A matching GitHub repo is a strong signal that a CVE has a public working exploit.
    """

    def fetch(self) -> List[ThreatRecord]:
        # TODO: search GitHub API with query "CVE poc exploit"
        # Filter by created date using self.config["lookback_days"]
        # Respect GitHub API rate limits (60 req/hr unauthenticated, 5000 with token)
        raise NotImplementedError

    def normalize(self, raw: dict) -> ThreatRecord:
        # TODO: map GitHub repo fields to ThreatRecord
        # Extract CVE ID from repo name or description using regex
        # Key fields: full_name, description, html_url, created_at, stargazers_count
        raise NotImplementedError
