import logging
import yaml
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_STACK_PATH = "config/stack.yaml"
SKIP_KEYS = {"environment"}

# Static alias overrides for known assets.
# These take precedence over LLM-generated aliases and never hit the cache.
# Add entries here when an asset has well-known variants that must always be correct,
# or when the LLM-generated aliases for an asset are known to be insufficient.
ASSET_ALIASES: Dict[str, List[str]] = {
    "postgresql":     ["postgresql", "postgres"],
    "github-actions": ["github actions", "actions runner", "github/actions"],
    "react":          ["react", "reactjs", "react.js"],
    "next":           ["next.js", "nextjs", "vercel next"],
    "python":         ["python", "cpython"],
    "chrome":         ["chrome", "chromium", "google chrome"],
    "openssl":        ["openssl"],
    "openssh":        ["openssh", "open ssh"],
    "docker":         ["docker", "docker engine", "moby"],
    "node":           ["node.js", "nodejs", "node"],
    "npm":            ["npm", "node package manager"],
    "webpack":        ["webpack"],
    "babel":          ["babel", "@babel"],
    "vite":           ["vite", "vitejs"],
    "fastapi":        ["fastapi", "fast api"],
    "pydantic":       ["pydantic"],
    "httpx":          ["httpx"],
    "starlette":      ["starlette"],
    "uvicorn":        ["uvicorn"],
    "sqlalchemy":     ["sqlalchemy", "sql alchemy"],
    "pillow":         ["pillow", "pil", "python imaging library"],
    "cryptography":   ["cryptography", "pyca/cryptography"],
    "paramiko":       ["paramiko"],
    "werkzeug":       ["werkzeug"],
    "urllib3":        ["urllib3"],
    "requests":       ["requests", "python-requests"],
    "jinja2":         ["jinja2", "jinja"],
    "curl":           ["curl", "libcurl"],
    "git":            ["git", "git scm"],
    "ollama":         ["ollama"],
    "macos":          ["macos", "mac os", "osx", "apple macos"],
    "streamlit":      ["streamlit"],
    "pandas":         ["pandas"],
    "numpy":          ["numpy"],
}

# Minimum character length for a term to be used in keyword matching.
# Prevents short tokens from false-positiving on unrelated text.
MIN_ASSET_NAME_LENGTH = 4


def load_stack(stack_path: str = DEFAULT_STACK_PATH) -> dict:
    """Load and return the asset inventory from a YAML file."""
    with open(stack_path, "r") as f:
        return yaml.safe_load(f)


def get_all_assets(stack_path: str = DEFAULT_STACK_PATH) -> List[dict]:
    """
    Flatten all asset categories from stack.yaml into a single list.
    Each asset dict gets a 'category' key added to preserve its origin.
    Non-list values and keys in SKIP_KEYS are ignored.
    """
    stack = load_stack(stack_path)
    assets = []
    for category, items in stack.items():
        if category in SKIP_KEYS or not isinstance(items, list):
            continue
        for asset in items:
            assets.append({**asset, "category": category})
    return assets


def get_asset_names(stack_path: str = DEFAULT_STACK_PATH) -> List[str]:
    """
    Return a flat deduplicated list of all asset names from stack.yaml.
    Names are lowercased for consistent matching.
    """
    assets = get_all_assets(stack_path)
    seen = set()
    names = []
    for asset in assets:
        name = asset["name"].lower()
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def get_aliases_for_asset(
    asset_name: str,
    category: str = "",
    cache_path: str = "config/alias_cache.yaml",
    use_llm: bool = True,
) -> List[str]:
    """
    Return all known alias strings for a given asset name.
    Resolution order:
      1. ASSET_ALIASES static overrides (no LLM call, no cache lookup)
      2. alias_cache.yaml on-disk cache (no LLM call)
      3. LLM generation via alias_generator.generate_aliases() (one call, then cached)
      4. Fallback: list containing only the asset name

    Set use_llm=False to disable LLM generation (useful in tests or offline runs).
    """
    name = asset_name.lower()

    if name in ASSET_ALIASES:
        return ASSET_ALIASES[name]

    if use_llm and category:
        from src.ingestion.alias_generator import generate_aliases
        return generate_aliases(asset_name, category, cache_path=cache_path)

    return [name]


def get_all_search_terms(
    stack_path: str = DEFAULT_STACK_PATH,
    cache_path: str = "config/alias_cache.yaml",
    use_llm: bool = True,
) -> Dict[str, List[str]]:
    """
    Return a mapping of canonical asset name to all search terms for that asset.
    Assets with static ASSET_ALIASES entries use those directly.
    All other assets go through LLM alias generation (cached after first call).
    Used by the correlator keyword fallback and the chat pipeline asset detection.
    """
    assets = get_all_assets(stack_path)
    result = {}
    seen = set()

    for asset in assets:
        name = asset["name"].lower()
        if name in seen:
            continue
        seen.add(name)

        category = asset.get("category", "")
        result[name] = get_aliases_for_asset(
            name,
            category=category,
            cache_path=cache_path,
            use_llm=use_llm,
        )

    return result


def detect_asset_in_query(
    query: str,
    stack_path: str = DEFAULT_STACK_PATH,
    cache_path: str = "config/alias_cache.yaml",
    use_llm: bool = False,
) -> Optional[str]:
    """
    Scan a query string for any asset name or alias from the stack.
    Returns the canonical asset name if found, None otherwise.
    Only matches terms of MIN_ASSET_NAME_LENGTH or more characters.
    use_llm defaults to False here: query-time alias lookup should use
    the cache only. LLM generation happens at correlator run time, not
    during live chat queries.
    """
    query_lower = query.lower()
    search_terms = get_all_search_terms(
        stack_path=stack_path,
        cache_path=cache_path,
        use_llm=use_llm,
    )

    for canonical_name, terms in search_terms.items():
        for term in terms:
            if len(term) < MIN_ASSET_NAME_LENGTH:
                continue
            if term in query_lower:
                logger.debug(
                    "Asset detected in query: %s (matched term: %s)",
                    canonical_name, term
                )
                return canonical_name

    return None