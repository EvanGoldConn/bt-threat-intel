from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, Field


class ThreatRecord(BaseModel):
    """
    Normalized representation of a CVE or threat entry.
    All feed sources map their output to this model before storage.
    """
    cve_id: Optional[str] = None
    source: str
    title: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    reference_urls: List[str] = Field(default_factory=list)
    raw_data: dict = Field(default_factory=dict)


class EmbeddedRecord(BaseModel):
    """A ThreatRecord paired with its vector embedding."""
    record: ThreatRecord
    embedding: List[float]


class ExposureResult(BaseModel):
    """Result of correlating a ThreatRecord against the asset inventory."""
    threat_id: int
    asset_name: str
    asset_version: str
    is_exposed: bool
    rationale: str


class IRPlaybook(BaseModel):
    """Generated IR playbook for a confirmed exposure."""
    threat_id: int
    cve_id: Optional[str]
    steps: List[str]
    priority: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))