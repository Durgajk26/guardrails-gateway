"""
input_guards.py — Layer 1: pre-LLM safety checks.
"""

import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine

from .schemas import GuardrailViolation


_analyzer = AnalyzerEngine()
_anonymizer = AnonymizerEngine()

_loose_card_recognizer = PatternRecognizer(
    supported_entity="CREDIT_CARD",
    name="LooseCreditCardRecognizer",
    patterns=[
        Pattern(
            name="loose_card_pattern",
            regex=r"\b(?:\d[ -]?){12,18}\d\b",
            score=0.6,
        ),
    ],
)
_analyzer.registry.add_recognizer(_loose_card_recognizer)


PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|previous|above)", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|your\s+instructions)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*[:.]", re.IGNORECASE),
    re.compile(r"system\s*[:.]?\s*you\s+are\s+now", re.IGNORECASE),
    re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"show\s+me\s+(your\s+)?(system\s+)?(prompt|instructions)", re.IGNORECASE),
]


def check_prompt_injection(prompt: str) -> list[GuardrailViolation]:
    violations = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        match = pattern.search(prompt)
        if match:
            violations.append(GuardrailViolation(
                layer="input",
                rule="prompt_injection",
                severity="block",
                detail=f"Detected injection pattern: '{match.group(0)}'",
            ))
            break
    return violations


JAILBREAK_PATTERNS = [
    re.compile(r"\bDAN\b\s+(mode|persona)", re.IGNORECASE),
    re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    re.compile(r"developer\s+mode", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?unrestricted", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+(have\s+no|are\s+free\s+from)\s+restrictions?", re.IGNORECASE),
    re.compile(r"jailbroken", re.IGNORECASE),
]


def check_jailbreak(prompt: str) -> list[GuardrailViolation]:
    violations = []
    for pattern in JAILBREAK_PATTERNS:
        match = pattern.search(prompt)
        if match:
            violations.append(GuardrailViolation(
                layer="input",
                rule="jailbreak_attempt",
                severity="block",
                detail=f"Detected jailbreak pattern: '{match.group(0)}'",
            ))
            break
    return violations


PII_ENTITIES = [
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "PERSON",
    "LOCATION",
    "IBAN_CODE",
]


def detect_and_redact_pii(prompt: str) -> tuple[str, list[GuardrailViolation]]:
    results = _analyzer.analyze(
        text=prompt,
        entities=PII_ENTITIES,
        language="en",
    )

    if not results:
        return prompt, []

    anonymized = _anonymizer.anonymize(text=prompt, analyzer_results=results)

    found_types = {r.entity_type for r in results}
    violations = [
        GuardrailViolation(
            layer="input",
            rule="pii_redacted",
            severity="redact",
            detail=f"Redacted {entity_type.lower().replace('_', ' ')}",
        )
        for entity_type in sorted(found_types)
    ]

    return anonymized.text, violations


def run_input_guards(prompt: str) -> tuple[str, list[GuardrailViolation]]:
    all_violations = []

    all_violations.extend(check_prompt_injection(prompt))
    all_violations.extend(check_jailbreak(prompt))

    has_block = any(v.severity == "block" for v in all_violations)
    if has_block:
        return prompt, all_violations

    sanitized, pii_violations = detect_and_redact_pii(prompt)
    all_violations.extend(pii_violations)

    return sanitized, all_violations