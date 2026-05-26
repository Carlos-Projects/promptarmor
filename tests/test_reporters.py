import json
from datetime import datetime

from mcp_taxonomy import AttackCategory, Confidence, Severity

from promptarmor.models import PromptArmorEvent
from promptarmor.reporters.console import ConsoleReporter
from promptarmor.reporters.html import HTMLReporter
from promptarmor.reporters.json import JSONReporter


def make_event(**kwargs) -> PromptArmorEvent:
    defaults = dict(
        request_id="test-123",
        timestamp=datetime.now(),
        source="127.0.0.1",
        prompt="test prompt",
        filtered=True,
        action="block",
        category=AttackCategory.INJECTION,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        score=0.85,
        matched_rules=["pattern-1"],
    )
    defaults.update(kwargs)
    return PromptArmorEvent(**defaults)


class TestConsoleReporter:
    def test_report_event(self):
        reporter = ConsoleReporter()
        reporter.report_event(make_event())

    def test_report_summary(self):
        reporter = ConsoleReporter()
        reporter.report_summary([make_event(), make_event(action="allow")])

    def test_report_rule_match(self):
        reporter = ConsoleReporter()
        reporter.report_rule_match("rule-1", "block", "high score")


class TestJSONReporter:
    def test_report_event(self):
        reporter = JSONReporter()
        reporter.report_event(make_event())
        assert len(reporter.events) == 1

    def test_generate_report(self):
        reporter = JSONReporter()
        reporter.report_event(make_event())
        report = reporter.generate_report()
        data = json.loads(report)
        assert len(data) == 1
        assert data[0]["request_id"] == "test-123"

    def test_save(self, tmp_path):
        reporter = JSONReporter(output_dir=str(tmp_path))
        reporter.report_event(make_event())
        path = reporter.save("test_report.json")
        assert path is not None

    def test_multiple_events(self):
        reporter = JSONReporter()
        reporter.report_event(make_event(request_id="one"))
        reporter.report_event(make_event(request_id="two"))
        assert len(reporter.events) == 2

    def test_empty_events(self):
        reporter = JSONReporter()
        report = reporter.generate_report()
        assert report == "[]"


class TestHTMLReporter:
    def test_report_event(self):
        reporter = HTMLReporter()
        reporter.report_event(make_event())
        reporter.report_event(make_event(action="allow"))
        assert len(reporter._events) == 2

    def test_generate_report(self):
        reporter = HTMLReporter()
        reporter.report_event(make_event())
        html = reporter.generate_report()
        assert "<!DOCTYPE html>" in html
        assert "PromptArmor Report" in html

    def test_save(self, tmp_path):
        reporter = HTMLReporter(output_dir=str(tmp_path))
        reporter.report_event(make_event())
        path = reporter.save("test.html")
        assert path is not None

    def test_empty_report(self):
        reporter = HTMLReporter()
        html = reporter.generate_report()
        assert "0" in html

    def test_stats_in_report(self):
        reporter = HTMLReporter()
        reporter.report_event(make_event(action="block"))
        reporter.report_event(make_event(action="flag"))
        reporter.report_event(make_event(action="allow"))
        html = reporter.generate_report()
        assert "Blocked" in html
        assert "Flagged" in html
        assert "Allowed" in html
