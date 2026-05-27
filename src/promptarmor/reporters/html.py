from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from promptarmor.models import PromptArmorEvent

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<title>PromptArmor Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
  h1 { font-size: 1.8rem; margin-bottom: 0.5rem; color: #38bdf8; }
  .subtitle { color: #94a3b8; margin-bottom: 2rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #1e293b; padding: 1rem; border-radius: 8px; text-align: center; }
  .stat-value { font-size: 2rem; font-weight: bold; }
  .stat-label { font-size: 0.85rem; color: #94a3b8; }
  .stat.blocked .stat-value { color: #ef4444; }
  .stat.flagged .stat-value { color: #f59e0b; }
  .stat.allowed .stat-value { color: #22c55e; }
  .stat.total .stat-value { color: #38bdf8; }
  .event { background: #1e293b; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; border-left: 4px solid #38bdf8; }
  .event.blocked { border-left-color: #ef4444; }
  .event.flagged { border-left-color: #f59e0b; }
  .event.allowed { border-left-color: #22c55e; }
  .event-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
  .event-id { font-weight: bold; }
  .event-action { font-size: 0.85rem; padding: 0.2rem 0.6rem; border-radius: 4px; background: #334155; }
  .event-action.blocked { background: #7f1d1d; color: #fca5a5; }
  .event-action.flagged { background: #713f12; color: #fcd34d; }
  .event-action.allowed { background: #166534; color: #86efac; }
  .event-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 0.5rem; }
  .field { }
  .field-label { font-size: 0.75rem; color: #64748b; }
  .prompt { margin-top: 0.5rem; padding: 0.5rem; background: #0f172a; border-radius: 4px; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap; word-break: break-all; max-height: 100px; overflow-y: auto; }
  .footer { margin-top: 2rem; text-align: center; color: #475569; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>🛡️ PromptArmor Report</h1>
<p class=\"subtitle\">Generated: {{ generated_at }} | Events: {{ events|length }}</p>

<div class=\"summary\">
  <div class=\"stat total\">
    <div class=\"stat-value\">{{ events|length }}</div>
    <div class=\"stat-label\">Total Events</div>
  </div>
  <div class=\"stat blocked\">
    <div class=\"stat-value\">{{ blocked_count }}</div>
    <div class=\"stat-label\">Blocked</div>
  </div>
  <div class=\"stat flagged\">
    <div class=\"stat-value\">{{ flagged_count }}</div>
    <div class=\"stat-label\">Flagged</div>
  </div>
  <div class=\"stat allowed\">
    <div class=\"stat-value\">{{ allowed_count }}</div>
    <div class=\"stat-label\">Allowed</div>
  </div>
</div>

{% for event in events %}
<div class=\"event {{ event.action }}\">
  <div class=\"event-header\">
    <span class=\"event-id\">{{ event.request_id }}</span>
    <span class=\"event-action {{ event.action }}\">{{ event.action|upper }}</span>
  </div>
  <div class=\"event-detail\">
    <div class=\"field\"><span class=\"field-label\">Source</span><br>{{ event.source }}</div>
    <div class=\"field\"><span class=\"field-label\">Category</span><br>{{ event.category }}</div>
    <div class=\"field\"><span class=\"field-label\">Severity</span><br>{{ event.severity }}</div>
    <div class=\"field\"><span class=\"field-label\">Score</span><br>{{ "%.2f"|format(event.score) }}</div>
  </div>
  <div class=\"prompt\">{{ event.prompt[:300] }}{% if event.prompt|length > 300 %}...{% endif %}</div>
</div>
{% endfor %}

<div class=\"footer\">PromptArmor v{{ version }} — Runtime Defense Toolkit</div>
</body>
</html>"""


class HTMLReporter:
    """Generates styled HTML reports from PromptArmor security events."""

    def __init__(self, output_dir: str | None = None, version: str = "0.1.0"):
        self.output_dir = Path(output_dir) if output_dir else None
        self.version = version
        self._template = Template(HTML_TEMPLATE)
        self._events: list[dict[str, Any]] = []

    def report_event(self, event: PromptArmorEvent) -> None:
        """Record a ``PromptArmorEvent`` for later HTML export."""
        self._events.append(
            {
                "request_id": event.request_id,
                "timestamp": event.timestamp.isoformat()
                if isinstance(event.timestamp, datetime)
                else str(event.timestamp),
                "source": event.source,
                "prompt": event.prompt,
                "filtered": event.filtered,
                "action": event.action,
                "category": event.category.value,
                "severity": event.severity.value,
                "confidence": event.confidence.value,
                "score": event.score,
                "matched_rules": event.matched_rules,
            }
        )

    def generate_report(self) -> str:
        """Render the HTML report from recorded events."""
        blocked = sum(1 for e in self._events if e["action"] == "block")
        flagged = sum(1 for e in self._events if e["action"] == "flag")
        allowed = sum(1 for e in self._events if e["action"] == "allow")

        return self._template.render(
            events=self._events,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            blocked_count=blocked,
            flagged_count=flagged,
            allowed_count=allowed,
            version=self.version,
        )

    def save(self, filename: str | None = None) -> str:
        """Write the HTML report to disk.

        Returns the path to the saved file.
        """
        path = filename or f"promptarmor_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            path = str(self.output_dir / path)
        html = self.generate_report()
        Path(path).write_text(html)
        return path
