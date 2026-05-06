"""
main.py — The FastAPI gateway entrypoint (Phase 3 — full pipeline).

REQUEST FLOW:
    POST /guard
        ↓
    Pydantic validates request
        ↓
    Layer 1: run_input_guards          — pattern detection, PII redaction
        ↓ (if any block → return blocked)
    Layer 2: run_policies              — YAML rule evaluation
        ↓ (if any block → return blocked)
    LLM call: call_llm(sanitized)      — actual model call
        ↓
    Layer 3: run_output_guards         — toxicity, topic drift, PII leak
        ↓ (if any block → return blocked)
    Return response with all violations logged

ERROR HANDLING:
LLM calls can fail (timeout, network, server down). We catch and return
a 503 with a clear message instead of letting the exception bubble up.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .schemas import GuardedRequest, GuardedResponse
from .input_guards import run_input_guards
from .policy_engine import run_policies, load_policies
from .llm_client import call_llm
from .output_guards import run_output_guards


app = FastAPI(
    title="LLM Guardrails Gateway",
    description="Middleware that enforces safety, compliance, and structure on LLM calls.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.post("/guard", response_model=GuardedResponse)
async def guard(request: GuardedRequest) -> GuardedResponse:
    # ── LAYER 1: Input guards ──────────────────────────────────────
    sanitized_prompt, input_violations = run_input_guards(request.prompt)

    if any(v.severity == "block" for v in input_violations):
        return GuardedResponse(
            status="blocked",
            llm_response=None,
            sanitized_prompt=None,
            violations=input_violations,
            original_prompt=request.prompt,
        )

    # ── LAYER 2: Policy engine ─────────────────────────────────────
    policy_violations = run_policies(request.prompt)
    pre_llm_violations = input_violations + policy_violations

    if any(v.severity == "block" for v in pre_llm_violations):
        return GuardedResponse(
            status="blocked",
            llm_response=None,
            sanitized_prompt=None,
            violations=pre_llm_violations,
            original_prompt=request.prompt,
        )

    # ── LLM CALL ───────────────────────────────────────────────────
    try:
        raw_response = call_llm(sanitized_prompt)
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"LLM call failed: {e}",
        )

    # ── LAYER 3: Output guards ─────────────────────────────────────
    sanitized_response, output_violations = run_output_guards(raw_response)
    all_violations = pre_llm_violations + output_violations

    if any(v.severity == "block" for v in output_violations):
        return GuardedResponse(
            status="blocked",
            llm_response=None,
            sanitized_prompt=sanitized_prompt,
            violations=all_violations,
            original_prompt=request.prompt,
        )

    # ── ALLOWED: All three layers passed ───────────────────────────
    return GuardedResponse(
        status="allowed",
        llm_response=sanitized_response,
        sanitized_prompt=sanitized_prompt,
        violations=all_violations,
        original_prompt=request.prompt,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/policies")
async def get_policies():
    return {"rules": load_policies()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)