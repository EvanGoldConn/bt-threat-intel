import os
import logging

import anthropic

logger = logging.getLogger(__name__)

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 1024

_instance = None


class AnalysisClient:
    """
    Thin wrapper around the Anthropic SDK.
    All LLM calls in the analysis layer go through this class
    so the model and retry logic live in one place.
    Instantiated once as a module-level singleton via get_analysis_client().
    """

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """
        Send a prompt to Claude and return the text response.
        Raises on API errors after built-in SDK retries.
        """
        response = self.client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text

    def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        """
        Same as complete() but appends a JSON output instruction to the system prompt.
        Strips markdown code fences from the response before returning.
        Use when the caller expects a parseable JSON string back.
        """
        json_system = system_prompt + "\n\nRespond with valid JSON only. No explanation, no markdown."
        raw = self.complete(json_system, user_prompt)
        return raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()


def get_analysis_client() -> AnalysisClient:
    """Return the shared AnalysisClient instance, creating it on first call."""
    global _instance
    if _instance is None:
        _instance = AnalysisClient()
    return _instance

