from dataclasses import dataclass, field

from mcp_taxonomy import AttackCategory, Confidence, Severity

REFLECTION_TRIGGERS: list[str] = [
    "ignore all instructions",
    "forget previous instructions",
    "disregard your guidelines",
    "you are now",
    "act as if",
    "override your",
    "new instructions",
    "from now on",
    "for the purpose of this",
    "this is a simulation",
    "hypothetical scenario",
    "jailbreak",
    "bypass safety",
    "output the above",
    "repeat everything",
    "reveal your prompt",
    "system prompt",
    "print your instructions",
    "do anything",
    "no restrictions",
    "no rules",
    "uncensored",
    "unfiltered",
    "unconstrained",
    "developer mode",
    "sudo mode",
    "dan mode",
]


@dataclass
class ReflectionResult:
    detected: bool
    reasoning: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.NONE
    category: AttackCategory = AttackCategory.POLICY_VIOLATION
    triggers: list[str] = field(default_factory=list)
    score: float = 0.0


class SelfReflectionGuard:
    def __init__(self, threshold: float = 0.1):
        self.threshold = threshold
        self._triggers = REFLECTION_TRIGGERS

    def analyze(self, text: str) -> ReflectionResult:
        if not text:
            return ReflectionResult(detected=False)

        lower = text.lower()
        triggered: list[str] = []
        for trigger in self._triggers:
            if trigger in lower:
                triggered.append(trigger)

        if not triggered:
            return ReflectionResult(detected=False)

        score = min(len(triggered) * 0.35, 1.0)
        reasoning = self._build_reasoning(triggered, score)

        if score >= 0.8:
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        elif score >= 0.5:
            severity = Severity.HIGH
            confidence = Confidence.MEDIUM
        else:
            severity = Severity.MEDIUM
            confidence = Confidence.LOW

        return ReflectionResult(
            detected=score >= self.threshold,
            reasoning=reasoning,
            severity=severity,
            confidence=confidence,
            category=AttackCategory.JAILBREAK,
            triggers=triggered,
            score=score,
        )

    @staticmethod
    def _build_reasoning(triggers: list[str], score: float) -> str:
        trigger_list = ", ".join(triggers[:5])
        if len(triggers) > 5:
            trigger_list += f" (+{len(triggers) - 5} more)"
        return (
            f"Self-reflection analysis found {len(triggers)} adversarial trigger(s): "
            f"[{trigger_list}]. "
            f"Confidence score: {score:.2f}. "
            f"The prompt attempts to manipulate model behavior by overriding "
            f"instructions or simulating roleplay scenarios."
        )
