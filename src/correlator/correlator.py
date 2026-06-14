import yaml
import logging
from typing import List

from src.ingestion.models import ThreatRecord, ExposureResult

logger = logging.getLogger(__name__)

DEFAULT_STACK_PATH = "config/stack.yaml"


class AssetCorrelator:
    """
    Loads the asset inventory from stack.yaml and cross-references it
    against incoming ThreatRecords to identify confirmed or probable exposures.
    Matching is done by software name and version range comparison.
    """

    def __init__(self, stack_path: str = DEFAULT_STACK_PATH):
        self.stack = self._load_stack(stack_path)

    def _load_stack(self, path: str) -> dict:
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def correlate(self, record: ThreatRecord, threat_id: int) -> List[ExposureResult]:
        """
        Compare a ThreatRecord against all assets in the stack.
        Returns a list of ExposureResult objects for any matched assets.
        """
        # TODO: extract affected product/vendor from record.raw_data (NVD CPE data is useful here)
        # Compare against services, runtimes, and libraries in self.stack
        # For version matching, use simple string comparison first,
        # then upgrade to packaging.version for semver ranges
        raise NotImplementedError

    def get_all_assets(self) -> List[dict]:
        """Return a flat list of all defined assets across all stack categories."""
        # TODO: flatten services, runtimes, libraries, operating_systems from self.stack
        raise NotImplementedError
