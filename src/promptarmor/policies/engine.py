from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyAction(Enum):
    """Supported policy actions."""

    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"
    SANITIZE = "sanitize"
    LOG = "log"
    REDIRECT = "redirect"


@dataclass
class PolicyRule:
    """A single policy rule with conditions and an action.

    Attributes:
        id: Unique rule identifier.
        name: Human-readable rule name.
        description: Extended description of the rule's purpose.
        action: The action to take when the rule matches.
        priority: Evaluation priority (higher = evaluated first).
        enabled: Whether the rule is active.
        conditions: Dict of conditions (score_min, source, model, category, pattern).
        metadata: Arbitrary key-value metadata for the rule.
    """

    id: str
    name: str
    description: str
    action: PolicyAction
    priority: int = 0
    enabled: bool = True
    conditions: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyResult:
    """Result of evaluating a policy against a context.

    Attributes:
        matched: Whether any rule matched.
        action: The action prescribed by the matched rule.
        rule: The matched rule, if any.
        reason: Human-readable explanation.
        score: Detection score from the rule match.
        details: Additional match-specific details.
    """

    matched: bool
    action: PolicyAction
    rule: PolicyRule | None = None
    reason: str = ""
    score: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


class PolicyEngine:
    """Evaluates a set of ordered policy rules against a request context.

    Rules are sorted by priority (descending) and evaluated in order.
    The first matching rule determines the action.
    """

    def __init__(self, rules: list[PolicyRule] | None = None):
        self._rules: list[PolicyRule] = sorted(rules or [], key=lambda r: (-r.priority, r.id))
        self._stats: dict[str, int] = {
            "evaluated": 0,
            "blocked": 0,
            "allowed": 0,
            "flagged": 0,
            "sanitized": 0,
        }

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule and re-sort by priority."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: (-r.priority, r.id))

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns ``True`` if a rule was removed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def evaluate(self, context: dict[str, Any]) -> PolicyResult:
        """Evaluate the policy rules against the given context dict.

        Returns a ``PolicyResult`` with the action prescribed by the
        first matching rule, or ALLOW if no rule matches.
        """
        self._stats["evaluated"] += 1
        for rule in self._rules:
            if not rule.enabled:
                continue
            match_result = self._match_rule(rule, context)
            if match_result["matched"]:
                return self._build_result(rule, match_result)
        return PolicyResult(
            matched=False,
            action=PolicyAction.ALLOW,
            reason="No matching rules",
        )

    def _match_rule(self, rule: PolicyRule, context: dict[str, Any]) -> dict[str, Any]:
        """Test whether a rule matches the request context.

        Checks conditions in order: score_min, source, model, category, pattern.
        Returns a dict with ``matched``, ``score``, and ``details``.
        """
        conditions = rule.conditions
        score = 0.0
        details: dict[str, Any] = {}

        if "score_min" in conditions:
            context_score = context.get("score", 0.0)
            if context_score >= conditions["score_min"]:
                score = context_score
            else:
                return {"matched": False, "score": 0.0}

        if "source" in conditions:
            source = context.get("source", "")
            if isinstance(conditions["source"], list):
                if source not in conditions["source"]:
                    return {"matched": False, "score": 0.0}
            elif source != conditions["source"]:
                return {"matched": False, "score": 0.0}

        if "model" in conditions:
            model = context.get("model", "")
            allowed = conditions["model"]
            if isinstance(allowed, list):
                if model not in allowed:
                    return {"matched": False, "score": 0.0}
            elif model != allowed:
                return {"matched": False, "score": 0.0}

        if "category" in conditions:
            category = context.get("category", "")
            if category != conditions["category"]:
                return {"matched": False, "score": 0.0}

        if "pattern" in conditions:
            import re

            text = context.get("text", "")
            if not re.search(conditions["pattern"], text, re.IGNORECASE):
                return {"matched": False, "score": 0.0}

        return {"matched": True, "score": score, "details": details}

    @staticmethod
    def _build_result(rule: PolicyRule, match: dict[str, Any]) -> PolicyResult:
        """Construct a ``PolicyResult`` from a matched rule."""
        action_map = {
            PolicyAction.BLOCK: "blocked",
            PolicyAction.FLAG: "flagged",
            PolicyAction.SANITIZE: "sanitized",
        }
        reason = f"Rule '{rule.name}' ({rule.id}): {action_map.get(rule.action, rule.action.value)}"
        return PolicyResult(
            matched=True,
            action=rule.action,
            rule=rule,
            reason=reason,
            score=match.get("score", 0.0),
            details=match.get("details", {}),
        )

    def stats(self) -> dict[str, int]:
        """Return a copy of the policy engine statistics."""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset all policy engine statistics to zero."""
        for key in self._stats:
            self._stats[key] = 0
