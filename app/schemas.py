"""
schemas.py — Pydantic models defining the shape of requests and responses.

WHY THIS FILE EXISTS:
Pydantic models are the contract between the user and the API. They:
  1. Validate incoming requests (reject malformed JSON automatically)
  2. Document the API (FastAPI builds Swagger docs from these)
  3. Type-check our internal code (the IDE catches errors before runtime)

Think of these as the "vocabulary" of the gateway — every other file
will refer to these types when sending data around.
"""

from typing import Optional
from pydantic import BaseModel, Field


# ─────────────────────────────────────────
# REQUEST MODEL — what users send us
# ─────────────────────────────────────────
class GuardedRequest(BaseModel):
    """
    A user's request to the gateway.

    The 'prompt' field is what they want to send to the LLM.
    Everything else is optional metadata.
    """
    prompt: str = Field(
        ...,                           # ... means "required"
        min_length=1,
        max_length=10_000,
        description="The user's message to send to the LLM",
    )
    user_id: Optional[str] = Field(
        default=None,
        description="Optional user ID for logging and rate limiting",
    )


# ─────────────────────────────────────────
# RESPONSE MODELS — what we send back
# ─────────────────────────────────────────
class GuardrailViolation(BaseModel):
    """
    Describes a single thing the guardrails caught.

    Multiple violations can occur in one request, so the gateway
    response includes a LIST of these.
    """
    layer: str          # "input" | "policy" | "output"
    rule: str           # human-readable rule name, e.g. "prompt_injection"
    severity: str       # "block" | "redact" | "warn"
    detail: str         # explanation for the user/logs


class GuardedResponse(BaseModel):
    """
    The gateway's response.

    There are three possible outcomes:
      1. Allowed → status="allowed", llm_response is the LLM's answer
      2. Blocked → status="blocked", violations explains why
      3. Redacted → status="allowed", but sanitized_prompt shows what was changed
    """
    status: str         # "allowed" | "blocked"
    llm_response: Optional[str] = None
    sanitized_prompt: Optional[str] = None     # set if PII was redacted
    violations: list[GuardrailViolation] = []  # empty list = no issues
    original_prompt: str                        # always echoed back for audit