from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from mcp_taxonomy import Severity

_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class AdaptiveDefense:
    def __init__(
        self,
        learning_rate: float = 0.1,
        decay_days: int = 30,
        min_confidence_threshold: float = 0.3,
        state_path: str | None = None,
    ):
        self.learning_rate = learning_rate
        self.decay_window = timedelta(days=decay_days)
        self.min_confidence = min_confidence_threshold
        self.state_path = Path(state_path) if state_path else None

        self._pattern_freq: dict[str, int] = defaultdict(int)
        self._pattern_severity: dict[str, list[int]] = defaultdict(list)
        self._ip_reputation: dict[str, list[float]] = defaultdict(list)
        self._model_attacks: dict[str, int] = defaultdict(int)
        self._total_events: int = 0
        self._last_decay: datetime = datetime.now()

    def record_event(
        self,
        pattern: str,
        severity: Severity,
        source_ip: str = "",
        model: str = "",
    ) -> None:
        self._pattern_freq[pattern] += 1
        self._pattern_severity[pattern].append(_SEVERITY_WEIGHTS.get(severity, 3))
        if source_ip:
            self._ip_reputation[source_ip].append(1.0)
        if model:
            self._model_attacks[model] += 1
        self._total_events += 1
        self._maybe_decay()

    def get_pattern_risk(self, pattern: str) -> float:
        freq = self._pattern_freq.get(pattern, 0)
        if freq == 0:
            return 0.0
        severities = self._pattern_severity.get(pattern, [])
        avg_severity = sum(severities) / len(severities) if severities else 0
        return min((freq * self.learning_rate) * (avg_severity / 5.0), 1.0)

    def get_ip_risk(self, source_ip: str) -> float:
        scores = self._ip_reputation.get(source_ip, [])
        if not scores:
            return 0.0
        return min(sum(scores) * self.learning_rate, 1.0)

    def get_dynamic_threshold(self, model: str = "") -> float:
        base = 0.5
        if model and self._model_attacks.get(model, 0) > 10:
            base += 0.2
        if self._total_events > 100:
            base += 0.1
        return min(base, 1.0)

    def get_emerging_patterns(self, min_freq: int = 5) -> list[dict[str, Any]]:
        emerging: list[dict[str, Any]] = []
        for pattern, freq in self._pattern_freq.items():
            if freq >= min_freq:
                severities = self._pattern_severity.get(pattern, [])
                emerging.append(
                    {
                        "pattern": pattern,
                        "frequency": freq,
                        "avg_severity": sum(severities) / len(severities) if severities else 0,
                        "risk": self.get_pattern_risk(pattern),
                    }
                )
        return sorted(emerging, key=lambda x: x["frequency"], reverse=True)

    def get_recommended_rules(self) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        for p in self.get_emerging_patterns(min_freq=10):
            if p["risk"] >= self.min_confidence:
                rules.append(
                    {
                        "pattern": p["pattern"],
                        "risk": p["risk"],
                        "suggested_action": "block" if p["risk"] >= 0.7 else "flag",
                    }
                )
        return rules

    def _maybe_decay(self) -> None:
        now = datetime.now()
        if now - self._last_decay > self.decay_window:
            for key in list(self._pattern_freq.keys()):
                self._pattern_freq[key] = max(self._pattern_freq[key] - 1, 0)
                if self._pattern_freq[key] == 0:
                    del self._pattern_freq[key]
            self._last_decay = now

    def stats(self) -> dict[str, Any]:
        return {
            "total_events": self._total_events,
            "unique_patterns": len(self._pattern_freq),
            "unique_ips": len(self._ip_reputation),
            "models_under_attack": dict(self._model_attacks),
            "dynamic_threshold": self.get_dynamic_threshold(),
            "emerging_patterns": len(self.get_emerging_patterns()),
        }

    def save_state(self, path: str | None = None) -> str:
        save_path = Path(path) if path else self.state_path
        if not save_path:
            save_path = Path(f"promptarmor_defense_state_{datetime.now().strftime('%Y%m%d')}.json")
        state = {
            "pattern_freq": dict(self._pattern_freq),
            "ip_reputation": {k: list(v) for k, v in self._ip_reputation.items()},
            "model_attacks": dict(self._model_attacks),
            "total_events": self._total_events,
        }
        save_path.write_text(json.dumps(state, indent=2))
        return str(save_path)

    def load_state(self, path: str) -> None:
        data = json.loads(Path(path).read_text())
        self._pattern_freq = defaultdict(int, data.get("pattern_freq", {}))
        self._ip_reputation = defaultdict(list, {k: list(v) for k, v in data.get("ip_reputation", {}).items()})
        self._model_attacks = defaultdict(int, data.get("model_attacks", {}))
        self._total_events = data.get("total_events", 0)
