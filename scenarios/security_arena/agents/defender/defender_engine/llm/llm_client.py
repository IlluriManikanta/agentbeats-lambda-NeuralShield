"""LLM client for the baseline defender.

This is the ONLY module that is allowed to call the model API.
All other components must be purely rule-based.
"""

from __future__ import annotations

import os
from typing import Optional

from openai import AsyncOpenAI

from ..config import (
    DEFAULT_MODEL,
    OPENAI_API_KEY_ENV,
    OPENAI_BASE_URL_ENV,
    SYSTEM_PROMPT,
)


_client: AsyncOpenAI | None = None


def _get_client() -> AsyncOpenAI:
    """
    Lazily construct the AsyncOpenAI client using configured environment values.

    This keeps startup cost low and ensures the client is only created when
    the policy actually allows an LLM call.
    """
    global _client
    if _client is None:
        api_key = os.getenv(OPENAI_API_KEY_ENV, "")
        base_url = os.getenv(OPENAI_BASE_URL_ENV, "")
        _client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    return _client


async def generate_response(user_prompt: str, model: Optional[str] = None) -> str:
    """
    Generate a response from the LLM given a user prompt.

    This function must be the ONLY place where the model API is called.
    It uses a defensive system prompt to reinforce safety.
    """
    client = _get_client()
    model_name = model or DEFAULT_MODEL

    response = await client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    content = response.choices[0].message.content
    return content or ""


