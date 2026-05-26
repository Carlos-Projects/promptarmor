from promptarmor.policies.engine import PolicyAction, PolicyEngine, PolicyResult, PolicyRule


class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_empty_engine_allows(self):
        result = self.engine.evaluate({"score": 0.0})
        assert not result.matched
        assert result.action == PolicyAction.ALLOW

    def test_add_rule(self):
        rule = PolicyRule(
            id="test-1",
            name="Test Block",
            description="Block high scores",
            action=PolicyAction.BLOCK,
            priority=100,
            conditions={"score_min": 0.8},
        )
        self.engine.add_rule(rule)
        result = self.engine.evaluate({"score": 0.9})
        assert result.matched
        assert result.action == PolicyAction.BLOCK

    def test_remove_rule(self):
        rule = PolicyRule(id="test-1", name="Test", description="", action=PolicyAction.BLOCK)
        self.engine.add_rule(rule)
        assert self.engine.remove_rule("test-1")
        assert not self.engine.remove_rule("nonexistent")

    def test_disabled_rule(self):
        rule = PolicyRule(
            id="disabled",
            name="Disabled",
            description="",
            action=PolicyAction.BLOCK,
            enabled=False,
            conditions={"score_min": 0.0},
        )
        self.engine.add_rule(rule)
        result = self.engine.evaluate({"score": 0.9})
        assert not result.matched

    def test_policy_result_dataclass(self):
        rule = PolicyRule(id="r1", name="R1", description="", action=PolicyAction.BLOCK)
        result = PolicyResult(matched=True, action=PolicyAction.BLOCK, rule=rule, reason="test")
        assert isinstance(result, PolicyResult)
        assert result.matched
        assert result.action == PolicyAction.BLOCK

    def test_priority_ordering(self):
        low = PolicyRule(id="low", name="Low", description="", action=PolicyAction.ALLOW, priority=0)
        high = PolicyRule(id="high", name="High", description="", action=PolicyAction.BLOCK, priority=100)
        engine = PolicyEngine(rules=[low, high])
        result = engine.evaluate({"score": 0.9})
        assert result.rule.id == "high"

    def test_source_condition(self):
        rule = PolicyRule(
            id="src",
            name="Source",
            description="",
            action=PolicyAction.BLOCK,
            conditions={"source": "internal"},
        )
        self.engine.add_rule(rule)
        assert self.engine.evaluate({"source": "internal", "score": 0.0}).matched
        assert not self.engine.evaluate({"source": "external", "score": 0.0}).matched

    def test_model_condition(self):
        rule = PolicyRule(
            id="model",
            name="Model",
            description="",
            action=PolicyAction.BLOCK,
            conditions={"model": "gpt-4"},
        )
        self.engine.add_rule(rule)
        assert self.engine.evaluate({"model": "gpt-4", "score": 0.0}).matched
        assert not self.engine.evaluate({"model": "claude", "score": 0.0}).matched

    def test_category_condition(self):
        rule = PolicyRule(
            id="cat",
            name="Cat",
            description="",
            action=PolicyAction.BLOCK,
            conditions={"category": "injection"},
        )
        self.engine.add_rule(rule)
        result = self.engine.evaluate({"category": "injection", "score": 0.0})
        assert result.matched

    def test_pattern_condition(self):
        rule = PolicyRule(
            id="pat",
            name="Pattern",
            description="",
            action=PolicyAction.BLOCK,
            conditions={"pattern": "jailbreak"},
        )
        self.engine.add_rule(rule)
        assert self.engine.evaluate({"text": "this is a jailbreak attempt", "score": 0.0}).matched
        assert not self.engine.evaluate({"text": "safe text", "score": 0.0}).matched

    def test_stats(self):
        self.engine.evaluate({"score": 0.0})
        self.engine.evaluate({"score": 0.0})
        stats = self.engine.stats()
        assert stats["evaluated"] == 2
        assert stats["allowed"] == 0

    def test_reset_stats(self):
        self.engine.evaluate({"score": 0.0})
        self.engine.reset_stats()
        stats = self.engine.stats()
        assert stats["evaluated"] == 0

    def test_flag_action(self):
        rule = PolicyRule(
            id="flag",
            name="Flag",
            description="",
            action=PolicyAction.FLAG,
            conditions={"score_min": 0.5},
        )
        self.engine.add_rule(rule)
        result = self.engine.evaluate({"score": 0.6})
        assert result.action == PolicyAction.FLAG

    def test_sanitize_action(self):
        rule = PolicyRule(
            id="san",
            name="Sanitize",
            description="",
            action=PolicyAction.SANITIZE,
            conditions={"score_min": 0.3},
        )
        self.engine.add_rule(rule)
        result = self.engine.evaluate({"score": 0.4})
        assert result.action == PolicyAction.SANITIZE
