"""
llm_client.py — A thin wrapper around the LLM API.

WHY A SEPARATE FILE?
The whole point of the gateway is that it works with ANY LLM. By isolating
the LLM-calling logic in one file, we can swap Ollama for OpenAI, Gemini,
Anthropic, or anything else by editing only this file.

The rest of the codebase calls one function — call_llm(prompt) — and
doesn't care what provider is behind it.

CURRENT IMPLEMENTATION:
Local Ollama via HTTP. Ollama exposes an OpenAI-compatible API at
localhost:11434, so we just send a POST request and parse the response.
"""

import httpx


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"
TIMEOUT_SECONDS = 180


def call_llm(prompt: str) -> str:
    """
    Send a prompt to the local Ollama instance and return its response.

    Args:
        prompt — the (sanitized) user prompt to send

    Returns:
        The LLM's text response

    Raises:
        httpx.HTTPError on network or server errors
        RuntimeError if the response shape is unexpected
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,            # We want one full response, not streaming
        "options": {
            "temperature": 0.3,     # Slight creativity, mostly factual
        },
    }

    with httpx.Client(timeout=TIMEOUT_SECONDS) as client:
        response = client.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        data = response.json()

    if "response" not in data:
        raise RuntimeError(f"Unexpected Ollama response shape: {data}")

    return data["response"]