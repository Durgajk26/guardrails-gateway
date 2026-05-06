"""
test_policy_engine.py — Layer 2 tests.

WHAT WE TEST:
  - keyword_block fires on competitor mentions
  - topic_block fires on medical advice
  - required_topic fires on off-topic prompts
  - All rules can fire together (multi-violation per request)
  - Empty/unknown rule types are skipped silently
"""

from app.policy_engine import (
    run_policies,
    _eval_keyword_block,
    _eval_topic_block,
    _eval_required_topic,
)


# ─────────────────────────────────────────
# Individual rule evaluators
# ─────────────────────────────────────────
class TestEvaluators:
    def test_keyword_block_fires_on_match(self):
        rule = {
            "name": "test_rule",
            "type": "keyword_block",
            "severity": "block",
            "keywords": ["forbidden_word"],
        }
        violation = _eval_keyword_block(rule, "Contains the forbidden_word here")
        assert violation is not None
        assert violation.rule == "test_rule"
        assert "forbidden_word" in violation.detail

    def test_keyword_block_clean_returns_none(self):
        rule = {"name": "x", "type": "keyword_block", "severity": "block", "keywords": ["nope"]}
        assert _eval_keyword_block(rule, "Clean prompt") is None

    def test_required_topic_fires_when_no_keyword_present(self):
        rule = {
            "name": "must_be_about_x",
            "type": "required_topic",
            "severity": "block",
            "keywords": ["refund", "shipping"],
        }
        # No keywords present → off-topic → violation
        violation = _eval_required_topic(rule, "Tell me about quantum physics")
        assert violation is not None

    def test_required_topic_passes_when_keyword_present(self):
        rule = {
            "name": "must_be_about_x",
            "type": "required_topic",
            "severity": "block",
            "keywords": ["refund", "shipping"],
        }
        # Has the keyword → on-topic → no violation
        assert _eval_required_topic(rule, "I need a refund please") is None


# ─────────────────────────────────────────
# Full engine runner
# ─────────────────────────────────────────
class TestRunPolicies:
    def test_clean_customer_service_query_passes(self):
        violations = run_policies("How long does shipping take?")
        # Should have no violations against our default policies
        assert all(v.severity != "block" for v in violations)

    def test_competitor_mention_is_blocked(self):
        # Default YAML has 'Globex' in no_competitor_mentions
        violations = run_policies("Compare your shipping to Globex shipping")
        block_violations = [v for v in violations if v.severity == "block"]
        # At least one block-level violation should fire
        assert len(block_violations) >= 1
        assert any("competitor" in v.rule for v in block_violations)

    def test_medical_advice_is_blocked(self):
        violations = run_policies("What dosage of medicine should I take?")
        assert any("medical" in v.rule for v in violations)

    def test_off_topic_is_blocked(self):
        violations = run_policies("What is the capital of France?")
        assert any("topic" in v.rule for v in violations)

    def test_multiple_rules_can_fire_simultaneously(self):
        # This prompt is BOTH off-topic AND mentions medical terms
        violations = run_policies("What dosage of dizziness medicine should I take?")
        rule_names = {v.rule for v in violations}
        # Should fire BOTH medical AND off-topic rules
        assert len(rule_names) >= 2