from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcp_taxonomy import AttackCategory, Confidence, Severity

INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|above|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?)", re.IGNORECASE),
    re.compile(r"system\s+prompt[:\s]", re.IGNORECASE),
    re.compile(r"you\s+are\s+(now|not)\s+(an?\s+)?(assistant|ai|bot)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+)?(you\s+are\s+)?(dan|developer\s+mode|sudo)", re.IGNORECASE),
    re.compile(r"do\s+(not\s+)?(what|as)\s+(i|we)\s+say", re.IGNORECASE),
    re.compile(r"output\s+(the\s+)?(above|previous)\s+(text|prompt|instructions?)", re.IGNORECASE),
    re.compile(r"reveal\s+(your|the)\s+(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"print\s+(your|the)\s+(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"repeat\s+(the\s+)?(above|previous|entire|all)\s+(text|prompt|instructions?)", re.IGNORECASE),
    re.compile(r"new\s+instructions?[:\s]", re.IGNORECASE),
    re.compile(r"override\s+(all\s+)?(instructions?|rules?|guidelines?)", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"<<[Ss][Yy][Ss][Tt][Ee][Mm]>>", re.IGNORECASE),
    re.compile(r"<\s*/\s*s\s*>", re.IGNORECASE),
    re.compile(r"role\s*[:=]\s*(system|assistant)", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]:?\s*", re.IGNORECASE),
    re.compile(r"\[\s*INST\s*\].*\[\s*/\s*INST\s*\]", re.IGNORECASE),
    re.compile(r"for\s+the\s+purpose\s+of\s+this\s+(simulation|roleplay|scenario)", re.IGNORECASE),
    re.compile(r"hypothetical\s+scenario", re.IGNORECASE),
    re.compile(r"this\s+is\s+(a\s+)?(simulation|roleplay|just\s+a\s+test)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"security\s+(measure|restriction|protocol|guideline)", re.IGNORECASE),
    re.compile(r"bypass\s+(security|safety|restriction|filter|guardrail)", re.IGNORECASE),
    re.compile(r"simulate\s+(unrestricted|uncensored)", re.IGNORECASE),
]


@dataclass
class DetectionResult:
    """Result of a single injection-detection scan.

    Attributes:
        detected: Whether the prompt tripped at least one pattern above threshold.
        severity: Severity level from mcp-taxonomy.
        confidence: Confidence level from mcp-taxonomy.
        category: Attack category (always INJECTION when detected).
        matched_patterns: List of pattern strings that matched.
        score: Detection score (0.0 to 1.0).
    """

    detected: bool
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.NONE
    category: AttackCategory = AttackCategory.POLICY_VIOLATION
    matched_patterns: list[str] = field(default_factory=list)
    score: float = 0.0


class InjectionDetector:
    """Pattern-based prompt injection detector.

    Scans input text against a curated list of regular expressions known
    to match prompt injection, jailbreak, and role-play manipulation attempts.
    """

    def __init__(self, threshold: float = 0.5, custom_patterns: list[str] | None = None):
        self.threshold = threshold
        self._patterns = list(INJECTION_PATTERNS)
        if custom_patterns:
            for p in custom_patterns:
                self._patterns.append(re.compile(p, re.IGNORECASE))

    def detect(self, text: str) -> DetectionResult:
        """Scan ``text`` for known injection patterns.

        Returns a ``DetectionResult`` with the matched patterns and a score
        proportional to the number of patterns hit.
        """
        if not text:
            return DetectionResult(detected=False)

        matches: list[str] = []
        for pattern in self._patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)

        if not matches:
            return DetectionResult(detected=False)

        raw_score = min(len(matches) / (len(self._patterns) or 1) * 10.0, 1.0)
        score = min(raw_score, 1.0)

        if score >= 0.8:
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        elif score >= 0.5:
            severity = Severity.HIGH
            confidence = Confidence.MEDIUM
        else:
            severity = Severity.MEDIUM
            confidence = Confidence.LOW

        return DetectionResult(
            detected=score >= self.threshold,
            severity=severity,
            confidence=confidence,
            category=AttackCategory.INJECTION,
            matched_patterns=matches,
            score=score,
        )
