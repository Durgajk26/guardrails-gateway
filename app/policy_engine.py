"""
policy_engine.py — Layer 2: configurable rules from YAML.

WHAT THIS FILE DOES:
Reads rules from a YAML file and evaluates each user prompt against them.
The Python code here is GENERIC — it doesn't know which competitors to block
or which topics to refuse. That knowledge lives entirely in the YAML.

DESIGN PATTERN:
This is the "rules engine" pattern. Each rule TYPE maps to one evaluator
function. Adding a new rule type = adding one function. Adding a new RULE
of an existing type = editing the YAML, no Python changes.

THREE RULE TYPES SUPPORTED:
  keyword_block    — block if prompt CONTAINS any keyword
  topic_block      — block if prompt is ABOUT a forbidden topic
  required_topic   — block if prompt is NOT about an allowed topic
"""

from pathlib import Path
import yaml

from .schemas import GuardrailViolation


POLICY_PATH = Path("policies/default.yaml")


# ─────────────────────────────────────────
# YAML loading
# ─────────────────────────────────────────
def load_policies(path: Path = POLICY_PATH) -> list[dict]:
    """
    Load rules from a YAML file.

    Why a function instead of a module-level constant?
    So we can reload policies without restarting the server. The endpoint
    can call this fresh on each request — the file system is fast.
    """
    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data.get("rules", []) if data else []


# ─────────────────────────────────────────
# Rule evaluators — one per rule type
# ─────────────────────────────────────────
def _eval_keyword_block(rule: dict, prompt: str) -> GuardrailViolation | None:
    """
    keyword_block: block if the prompt mentions ANY listed keyword.

    Use case: "never mention our competitors", "block our internal codenames"
    """
    prompt_lower = prompt.lower()
    for keyword in rule.get("keywords", []):
        if keyword.lower() in prompt_lower:
            return GuardrailViolation(
                layer="policy",
                rule=rule["name"],
                severity=rule.get("severity", "block"),
                detail=f"{rule.get('detail', 'Policy violation')}: matched '{keyword}'",
            )
    return None


def _eval_topic_block(rule: dict, prompt: str) -> GuardrailViolation | None:
    """
    topic_block: block if the prompt is ABOUT a forbidden topic.

    For Phase 2 we use keyword matching as a proxy for topic detection.
    In Phase 3 we'd upgrade this to use a topic classifier model — same
    interface, smarter implementation.
    """
    prompt_lower = prompt.lower()
    for keyword in rule.get("keywords", []):
        if keyword.lower() in prompt_lower:
            return GuardrailViolation(
                layer="policy",
                rule=rule["name"],
                severity=rule.get("severity", "block"),
                detail=rule.get("detail", "Topic not permitted"),
            )
    return None


def _eval_required_topic(rule: dict, prompt: str) -> GuardrailViolation | None:
    """
    required_topic: block if the prompt is NOT about an allowed topic.

    The inverse of topic_block. Use case: "this is a customer service bot,
    refuse anything off-topic." Particularly useful for narrowly-scoped
    chatbots that shouldn't be answering general questions.

    Logic: if NONE of the allowed keywords appear, it's off-topic.
    """
    prompt_lower = prompt.lower()
    keywords = rule.get("keywords", [])

    if any(kw.lower() in prompt_lower for kw in keywords):
        return None  # On topic — no violation

    return GuardrailViolation(
        layer="policy",
        rule=rule["name"],
        severity=rule.get("severity", "block"),
        detail=rule.get("detail", "Question is off-topic"),
    )


# ─────────────────────────────────────────
# Dispatch table — maps rule type → evaluator
# ─────────────────────────────────────────
# This is the heart of the engine. Each new rule type just adds one entry
# here. The main run_policies() function doesn't need changing.
_EVALUATORS = {
    "keyword_block": _eval_keyword_block,
    "topic_block": _eval_topic_block,
    "required_topic": _eval_required_topic,
}


# ─────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────
def run_policies(prompt: str) -> list[GuardrailViolation]:
    """
    Evaluate every rule in the policy file against the prompt.
    Returns a list of violations (empty if all rules passed).

    Note: we run ALL rules even after finding a violation. Why?
    Because the audit log should show every rule that fired,
    not just the first one. Useful for debugging policies.
    """
    rules = load_policies()
    violations = []

    for rule in rules:
        rule_type = rule.get("type")
        evaluator = _EVALUATORS.get(rule_type)

        if evaluator is None:
            continue  # Unknown rule type — skip silently

        violation = evaluator(rule, prompt)
        if violation:
            violations.append(violation)

    return violations