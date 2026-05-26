from pathlib import Path

from mcp_taxonomy import Severity

from promptarmor.filters.adaptive_defense import AdaptiveDefense


class TestAdaptiveDefense:
    def setup_method(self):
        self.ad = AdaptiveDefense(learning_rate=0.1)

    def test_record_event_increases_freq(self):
        self.ad.record_event("ignore instructions", Severity.HIGH)
        assert self.ad._pattern_freq["ignore instructions"] == 1

    def test_record_event_multiple_times(self):
        for _ in range(5):
            self.ad.record_event("jailbreak", Severity.CRITICAL)
        assert self.ad._pattern_freq["jailbreak"] == 5

    def test_pattern_risk_increases_with_freq(self):
        for _ in range(3):
            self.ad.record_event("test pattern", Severity.HIGH)
        risk = self.ad.get_pattern_risk("test pattern")
        assert risk > 0

    def test_unknown_pattern_risk_zero(self):
        risk = self.ad.get_pattern_risk("nonexistent")
        assert risk == 0.0

    def test_ip_risk_tracking(self):
        self.ad.record_event("test", Severity.LOW, source_ip="10.0.0.1")
        self.ad.record_event("test2", Severity.HIGH, source_ip="10.0.0.1")
        risk = self.ad.get_ip_risk("10.0.0.1")
        assert risk > 0

    def test_unknown_ip_risk_zero(self):
        assert self.ad.get_ip_risk("1.2.3.4") == 0.0

    def test_dynamic_threshold_default(self):
        assert self.ad.get_dynamic_threshold() == 0.5

    def test_dynamic_threshold_after_many_events(self):
        for _ in range(150):
            self.ad.record_event("test", Severity.MEDIUM)
        assert self.ad.get_dynamic_threshold() > 0.5

    def test_emerging_patterns_empty(self):
        assert self.ad.get_emerging_patterns() == []

    def test_emerging_patterns_with_data(self):
        for _ in range(10):
            self.ad.record_event("frequent pattern", Severity.HIGH)
        emerging = self.ad.get_emerging_patterns(min_freq=5)
        assert len(emerging) == 1
        assert emerging[0]["pattern"] == "frequent pattern"

    def test_recommended_rules(self):
        for _ in range(15):
            self.ad.record_event("dangerous pattern", Severity.CRITICAL)
        rules = self.ad.get_recommended_rules()
        assert len(rules) >= 1

    def test_stats(self):
        self.ad.record_event("pattern", Severity.HIGH)
        stats = self.ad.stats()
        assert stats["total_events"] == 1
        assert stats["unique_patterns"] == 1

    def test_save_and_load_state(self, tmp_path):
        self.ad.record_event("saved pattern", Severity.HIGH)
        path = self.ad.save_state(str(tmp_path / "state.json"))
        assert Path(path).exists()

        ad2 = AdaptiveDefense()
        ad2.load_state(path)
        assert ad2._total_events == 1
        assert "saved pattern" in ad2._pattern_freq

    def test_model_attack_tracking(self):
        self.ad.record_event("test", Severity.HIGH, model="gpt-4")
        self.ad.record_event("test2", Severity.CRITICAL, model="gpt-4")
        assert self.ad._model_attacks["gpt-4"] == 2

    def test_get_recommended_rules_empty(self):
        rules = self.ad.get_recommended_rules()
        assert rules == []

    def test_risk_bounded(self):
        for _ in range(100):
            self.ad.record_event("overflow", Severity.CRITICAL)
        risk = self.ad.get_pattern_risk("overflow")
        assert risk <= 1.0

    def test_severity_affects_risk(self):
        low = AdaptiveDefense(learning_rate=0.1)
        high = AdaptiveDefense(learning_rate=0.1)
        low.record_event("test", Severity.LOW)
        high.record_event("test", Severity.CRITICAL)
        assert high.get_pattern_risk("test") > low.get_pattern_risk("test")
