"""
main.py — The FastAPI gateway entrypoint.

REQUEST FLOW (Phase 2):
    POST /guard
        ↓
    Pydantic validates request
        ↓
    Layer 1: run_input_guards(prompt)        — pattern detection, PII redaction
        ↓
    Any 'block' from Layer 1?  → return blocked
        ↓
    Layer 2: run_policies(sanitized_prompt)  — YAML rule evaluation
        ↓
    Any 'block' from Layer 2?  → return blocked
        ↓
    Otherwise → return allowed (LLM call comes in Phase 3)

KEY DESIGN CHOICE:
We feed the SANITIZED prompt (post-PII-redaction) into the policy engine,
not the original. This means policy rules see <EMAIL_ADDRESS> instead of
the raw email — they enforce business rules, not security.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .schemas import GuardedRequest, GuardedResponse
from .input_guards import run_input_guards
from .policy_engine import run_policies


app = FastAPI(
    title="LLM Guardrails Gateway",
    description="Middleware that enforces safety, compliance, and structure on LLM calls.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.post("/guard", response_model=GuardedResponse)
async def guard(request: GuardedRequest) -> GuardedResponse:
    # ── LAYER 1: Input guards (pattern detection + PII) ────────────
    sanitized_prompt, input_violations = run_input_guards(request.prompt)

    has_block = any(v.severity == "block" for v in input_violations)
    if has_block:
        return GuardedResponse(
            status="blocked",
            llm_response=None,
            sanitized_prompt=None,
            violations=input_violations,
            original_prompt=request.prompt,
        )

    # ── LAYER 2: Policy engine (YAML rules) ────────────────────────
    policy_violations = run_policies(request.prompt)
    all_violations = input_violations + policy_violations

    has_block = any(v.severity == "block" for v in all_violations)
    if has_block:
        return GuardedResponse(
            status="blocked",
            llm_response=None,
            sanitized_prompt=None,
            violations=all_violations,
            original_prompt=request.prompt,
        )

    # ── ALLOWED: All layers passed (LLM call comes in Phase 3) ─────
    return GuardedResponse(
        status="allowed",
        llm_response="[Phase 2: LLM not yet wired up. Sanitized prompt would be sent.]",
        sanitized_prompt=sanitized_prompt,
        violations=all_violations,  # may include redact-level (PII) entries
        original_prompt=request.prompt,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "phase": 2, "version": "0.2.0"}


@app.get("/policies")
async def get_policies():
    """
    Inspect currently-loaded policies. Useful for debugging and for
    confirming a YAML edit was picked up without restarting the server.
    """
    from .policy_engine import load_policies
    return {"rules": load_policies()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)