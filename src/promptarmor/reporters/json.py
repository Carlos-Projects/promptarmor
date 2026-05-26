import json
from datetime import datetime
from pathlib import Path
from typing import Any

from promptarmor.models import PromptArmorEvent


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class JSONReporter:
    def __init__(self, output_dir: str | None = None):
        self.output_dir = Path(output_dir) if output_dir else None
        self._events: list[dict[str, Any]] = []

    def report_event(self, event: PromptArmorEvent) -> None:
        record = {
            "request_id": event.request_id,
            "timestamp": event.timestamp,
            "source": event.source,
            "prompt": event.prompt[:500] if event.prompt else "",
            "filtered": event.filtered,
            "action": event.action,
            "category": event.category.value,
            "severity": event.severity.value,
            "confidence": event.confidence.value,
            "score": event.score,
            "matched_rules": event.matched_rules,
            "response": event.response[:500] if event.response else None,
            "metadata": event.metadata,
        }
        self._events.append(record)

    def generate_report(self) -> str:
        return json.dumps(self._events, cls=DateTimeEncoder, indent=2)

    def save(self, filename: str | None = None) -> str:
        path = filename or f"promptarmor_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            path = str(self.output_dir / path)
        data = self.generate_report()
        Path(path).write_text(data)
        return path

    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)
