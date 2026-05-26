import re
from dataclasses import dataclass, field

from mcp_taxonomy import AttackCategory, Confidence, Severity

EXFILTRATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?:sk|api[_-]?key|token|secret|password|credential)[s]?\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}", re.IGNORECASE),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.(?:eyJ[a-zA-Z0-9_-]{10,}\.)", re.IGNORECASE),
    re.compile(r"(?:sk-[a-zA-Z0-9_\-]{20,})"),
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}"),
    re.compile(r"(?:-----BEGIN.*?KEY-----)", re.IGNORECASE | re.DOTALL),
]

HIDDEN_INSTRUCTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|messages?)"),
    re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|messages?)"),
    re.compile(r"(?i)say\s+the\s+word.*?(?:\"|\')"),
    re.compile(r"(?i)include\s+(?:the\s+)?(?:following|hidden)\s+(?:text|instruction)"),
    re.compile(r"(?i)<\s*style[^>]*>.*?<\s*/\s*style\s*>"),
    re.compile(r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>"),
    re.compile(r"(?i)color\s*[:=]\s*transparent"),
    re.compile(r"(?i)font-size\s*[:=]\s*0"),
    re.compile(r"(?i)opacity\s*[:=]\s*0"),
]


@dataclass
class ValidationResult:
    valid: bool
    has_exfiltration: bool = False
    has_hidden_instructions: bool = False
    exfiltration_matches: list[str] = field(default_factory=list)
    hidden_instruction_matches: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.NONE
    category: AttackCategory = AttackCategory.POLICY_VIOLATION


class OutputValidator:
    def __init__(
        self,
        check_exfiltration: bool = True,
        check_hidden_instructions: bool = True,
        max_output_length: int | None = None,
    ):
        self.check_exfiltration = check_exfiltration
        self.check_hidden_instructions = check_hidden_instructions
        self.max_output_length = max_output_length

    def validate(self, text: str) -> ValidationResult:
        if not text:
            return ValidationResult(valid=True)

        exfil_matches: list[str] = []
        hidden_matches: list[str] = []

        if self.check_exfiltration:
            for pattern in EXFILTRATION_PATTERNS:
                m = pattern.search(text)
                if m:
                    exfil_matches.append(m.group())

        if self.check_hidden_instructions:
            for pattern in HIDDEN_INSTRUCTION_PATTERNS:
                m = pattern.search(text)
                if m:
                    hidden_matches.append(m.group())

        has_exfiltration = len(exfil_matches) > 0
        has_hidden = len(hidden_matches) > 0
        valid = not (has_exfiltration or has_hidden)

        if has_exfiltration or has_hidden:
            severity = Severity.CRITICAL if has_exfiltration else Severity.HIGH
            confidence = Confidence.HIGH
            category = AttackCategory.EXFILTRATION if has_exfiltration else AttackCategory.JAILBREAK
        else:
            severity = Severity.INFO
            confidence = Confidence.NONE
            category = AttackCategory.POLICY_VIOLATION

        return ValidationResult(
            valid=valid,
            has_exfiltration=has_exfiltration,
            has_hidden_instructions=has_hidden,
            exfiltration_matches=exfil_matches,
            hidden_instruction_matches=hidden_matches,
            severity=severity,
            confidence=confidence,
            category=category,
        )
