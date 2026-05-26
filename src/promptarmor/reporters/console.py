from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from promptarmor.models import PromptArmorEvent


class ConsoleReporter:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def report_event(self, event: PromptArmorEvent) -> None:
        action_color = "red" if event.action == "block" else "yellow" if event.action == "flag" else "green"
        status = Text(f"[{event.action.upper()}]", style=f"bold {action_color}")

        panel = Panel(
            f"{status} Request: {event.request_id}\n"
            f"Source: {event.source}\n"
            f"Category: {event.category.value}\n"
            f"Severity: {event.severity.value}\n"
            f"Confidence: {event.confidence.value}\n"
            f"Score: {event.score:.2f}\n"
            f"Timestamp: {event.timestamp.isoformat()}",
            title="PromptArmor Event",
            border_style=action_color,
        )
        self.console.print(panel)

    def report_summary(self, events: list[PromptArmorEvent]) -> None:
        total = len(events)
        blocked = sum(1 for e in events if e.action == "block")
        flagged = sum(1 for e in events if e.action == "flag")
        allowed = sum(1 for e in events if e.action == "allow")

        table = Table(title="PromptArmor Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="bold")

        table.add_row("Total Events", str(total))
        table.add_row("Blocked", str(blocked))
        table.add_row("Flagged", str(flagged))
        table.add_row("Allowed", str(allowed))

        self.console.print(table)

    def report_rule_match(self, rule_id: str, action: str, reason: str) -> None:
        self.console.print(f"[dim]Rule[/dim] [bold]{rule_id}[/bold] → {action}: {reason}")
