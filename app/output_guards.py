"""
output_guards.py — Layer 3: post-LLM safety checks.

CHECKS:
  1. Toxicity detection — Detoxify ML model
  2. Topic drift — TWO-STAGE:
        Stage A: keyword ratio (fast filter, ~1ms)
        Stage B: LLM-as-judge (slow but accurate, ~1-2s)
     Stage B only runs if Stage A passes — performance optimisation.
  3. PII leak detection — Presidio re-applied to LLM output

DESIGN PRINCIPLE:
Cheap filters first, expensive ones only when needed.
Same pattern used in fraud detection and content moderation systems.
"""

import json
from detoxify import Detoxify

from .schemas import GuardrailViolation
from .input_guards import detect_and_redact_pii
from .policy_engine import load_policies
from .llm_client import call_llm


_toxicity_model = Detoxify("original")
TOXICITY_THRESHOLD = 0.5
TOPIC_KEYWORD_RATIO_MIN = 0.03  # 3% of words must be on-topic to skip stage B


# ─────────────────────────────────────────
# CHECK 1: Toxicity
# ─────────────────────────────────────────
def check_toxicity(response: str) -> list[GuardrailViolation]:
    if not response.strip():
        return []
    scores = _toxicity_model.predict(response)
    flagged = {
        category: float(score)
        for category, score in scores.items()
        if float(score) > TOXICITY_THRESHOLD
    }
    if not flagged:
        return []
    detail = "; ".join(f"{cat}={score:.2f}" for cat, score in flagged.items())
    return [GuardrailViolation(
        layer="output",
        rule="toxic_response",
        severity="block",
        detail=f"Toxic content detected — {detail}",
    )]


# ─────────────────────────────────────────
# CHECK 2A: Keyword ratio (fast filter)
# ─────────────────────────────────────────
def _keyword_ratio_check(response: str, keywords: list[str]) -> tuple[bool, float]:
    """
    Returns (on_topic, ratio).
    on_topic = True if at least TOPIC_KEYWORD_RATIO_MIN of the words match.
    Used as a fast pre-filter before the expensive LLM judge.
    """
    words = response.lower().split()
    if not words:
        return True, 1.0  # Empty response — pass cheaply, let other checks handle

    keyword_set = {kw.lower() for kw in keywords}
    matches = sum(1 for w in words if w.strip(".,!?;:()") in keyword_set)
    ratio = matches / len(words)
    return ratio >= TOPIC_KEYWORD_RATIO_MIN, ratio


# ─────────────────────────────────────────
# CHECK 2B: LLM-as-judge (slow but accurate)
# ─────────────────────────────────────────
def _llm_judge_topic_drift(response: str, allowed_topics_description: str) -> tuple[bool, str]:
    """
    Ask the LLM itself: 'did this response stay on topic?'

    Returns (on_topic, reason).
    Falls back to True (allow) on parse errors — biases toward letting
    responses through rather than blocking on judge failures.
    """
    judge_prompt = f"""You are a strict topic relevance evaluator.

Allowed topics: {allowed_topics_description}

Response to evaluate:
\"\"\"
{response}
\"\"\"

Did the response stay primarily on the allowed topics? A response that
significantly discusses unrelated subjects should be marked off-topic,
even if it briefly mentions the allowed topics.

Respond with valid JSON only:
{{
  "on_topic": true or false,
  "reason": "brief explanation"
}}"""

    try:
        raw = call_llm(judge_prompt).strip()
        # Strip markdown code fences if the model adds them
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        verdict = json.loads(raw)
        return bool(verdict.get("on_topic", True)), str(verdict.get("reason", ""))
    except (json.JSONDecodeError, KeyError, Exception):
        # Judge failure → bias toward allowing (don't block on infrastructure issues)
        return True, "Judge response could not be parsed"


# ─────────────────────────────────────────
# CHECK 2: Topic drift — two-stage orchestrator
# ─────────────────────────────────────────
def check_topic_drift(response: str) -> list[GuardrailViolation]:
    """
    Two-stage topic drift detection.
    Only runs if a 'required_topic' rule exists in the YAML.
    """
    rules = load_policies()
    required_topic_rules = [r for r in rules if r.get("type") == "required_topic"]

    if not required_topic_rules:
        return []

    violations = []

    for rule in required_topic_rules:
        keywords = rule.get("keywords", [])

        # Stage A: keyword ratio (fast)
        passed_keyword, ratio = _keyword_ratio_check(response, keywords)
        if not passed_keyword:
            violations.append(GuardrailViolation(
                layer="output",
                rule=f"topic_drift_{rule['name']}",
                severity="block",
                detail=f"Response has only {ratio:.1%} on-topic words ({rule.get('detail', '')})",
            ))
            continue  # Skip stage B for this rule, it already failed stage A

        # Stage B: LLM-as-judge (slow, only if stage A passed)
        topics_desc = ", ".join(keywords)
        on_topic, reason = _llm_judge_topic_drift(response, topics_desc)
        if not on_topic:
            violations.append(GuardrailViolation(
                layer="output",
                rule=f"topic_drift_{rule['name']}_judge",
                severity="block",
                detail=f"LLM judge flagged drift: {reason}",
            ))

    return violations


# ─────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────
def run_output_guards(response: str) -> tuple[str, list[GuardrailViolation]]:
    all_violations = []

    all_violations.extend(check_toxicity(response))
    all_violations.extend(check_topic_drift(response))

    if any(v.severity == "block" for v in all_violations):
        return response, all_violations

    sanitized, pii_violations = detect_and_redact_pii(response)
    pii_violations_relabeled = [
        GuardrailViolation(
            layer="output",
            rule=f"pii_leak_{v.rule}",
            severity=v.severity,
            detail=f"LLM response contained PII — {v.detail}",
        )
        for v in pii_violations
    ]
    all_violations.extend(pii_violations_relabeled)

    return sanitized, all_violations