from promptarmor.policies.engine import PolicyAction, PolicyRule
from promptarmor.policies.generator import MCPGuardPolicyGenerator


class TestMCPGuardPolicyGenerator:
    def setup_method(self):
        self.generator = MCPGuardPolicyGenerator()

    def test_generate_dict(self):
        rules = [
            PolicyRule(
                id="r1",
                name="Block",
                description="Block high",
                action=PolicyAction.BLOCK,
                conditions={"score_min": 0.8},
            ),
            PolicyRule(
                id="r2", name="Flag", description="Flag medium", action=PolicyAction.FLAG, conditions={"score_min": 0.5}
            ),
        ]
        result = self.generator.generate(rules)
        assert result["version"] == "1.0"
        assert result["namespace"] == "promptarmor"
        assert len(result["rules"]) == 2

    def test_generate_yaml(self):
        rules = [
            PolicyRule(id="r1", name="Block", description="", action=PolicyAction.BLOCK),
        ]
        yaml_str = self.generator.generate_yaml(rules)
        assert isinstance(yaml_str, str)
        assert "promptarmor_r1" in yaml_str

    def test_action_mapping_block(self):
        rules = [PolicyRule(id="r1", name="R1", description="", action=PolicyAction.BLOCK)]
        result = self.generator.generate(rules)
        assert result["rules"][0]["action"] == "deny"

    def test_action_mapping_allow(self):
        rules = [PolicyRule(id="r1", name="R1", description="", action=PolicyAction.ALLOW)]
        result = self.generator.generate(rules)
        assert result["rules"][0]["action"] == "allow"

    def test_action_mapping_flag(self):
        rules = [PolicyRule(id="r1", name="R1", description="", action=PolicyAction.FLAG)]
        result = self.generator.generate(rules)
        assert result["rules"][0]["action"] == "log"

    def test_action_mapping_sanitize(self):
        rules = [PolicyRule(id="r1", name="R1", description="", action=PolicyAction.SANITIZE)]
        result = self.generator.generate(rules)
        assert result["rules"][0]["action"] == "sanitize"

    def test_action_mapping_log(self):
        rules = [PolicyRule(id="r1", name="R1", description="", action=PolicyAction.LOG)]
        result = self.generator.generate(rules)
        assert result["rules"][0]["action"] == "log"

    def test_custom_namespace(self):
        gen = MCPGuardPolicyGenerator(namespace="myapp")
        rules = [PolicyRule(id="r1", name="R1", description="", action=PolicyAction.BLOCK)]
        result = gen.generate(rules)
        assert result["rules"][0]["id"] == "myapp_r1"

    def test_empty_rules(self):
        result = self.generator.generate([])
        assert len(result["rules"]) == 0

    def test_conditions_included(self):
        rules = [
            PolicyRule(
                id="r1",
                name="R1",
                description="",
                action=PolicyAction.BLOCK,
                conditions={"score_min": 0.8, "source": "api"},
            )
        ]
        result = self.generator.generate(rules)
        assert "conditions" in result["rules"][0]
        assert result["rules"][0]["conditions"]["score_min"] == 0.8
