
from promptarmor.policies.engine import PolicyAction, PolicyEngine
from promptarmor.policies.generator import MCPGuardPolicyGenerator
from promptarmor.policies.yaml_loader import YamlPolicyLoader

SAMPLE_POLICY = """
rules:
  - id: block-critical
    name: "Block Critical"
    description: "Block critical injections"
    action: block
    priority: 100
    conditions:
      score_min: 0.8

  - id: flag-medium
    name: "Flag Medium"
    description: "Flag medium risk"
    action: flag
    priority: 50
    conditions:
      score_min: 0.5

  - id: allow-safe
    name: "Allow Safe"
    action: allow
    priority: 0
    conditions:
      score_min: 0.0
"""


class TestPolicyIntegration:
    def test_full_policy_workflow(self):
        loader = YamlPolicyLoader()
        rules = loader.loads(SAMPLE_POLICY)
        assert len(rules) == 3

        engine = PolicyEngine(rules=rules)

        result_block = engine.evaluate({"score": 0.9})
        assert result_block.action == PolicyAction.BLOCK
        assert result_block.matched

        result_flag = engine.evaluate({"score": 0.6})
        assert result_flag.action == PolicyAction.FLAG

        result_allow = engine.evaluate({"score": 0.1})
        assert result_allow.action == PolicyAction.ALLOW

    def test_load_generate_cycle(self):
        loader = YamlPolicyLoader()
        rules = loader.loads(SAMPLE_POLICY)

        gen = MCPGuardPolicyGenerator()
        output = gen.generate(rules)

        assert output["version"] == "1.0"
        assert len(output["rules"]) == 3

        rule_ids = [r["id"] for r in output["rules"]]
        assert "promptarmor_block-critical" in rule_ids

    def test_yaml_roundtrip(self):
        loader = YamlPolicyLoader()
        rules = loader.loads(SAMPLE_POLICY)

        gen = MCPGuardPolicyGenerator()
        yaml_output = gen.generate_yaml(rules)

        assert isinstance(yaml_output, str)
        assert "promptarmor_" in yaml_output

    def test_policy_from_file(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_POLICY)

        loader = YamlPolicyLoader()
        rules = loader.load(str(policy_file))
        assert len(rules) == 3

    def test_priority_ordering(self):
        loader = YamlPolicyLoader()
        rules = loader.loads(SAMPLE_POLICY)
        engine = PolicyEngine(rules=rules)

        assert engine.evaluate({"score": 0.9}).action == PolicyAction.BLOCK
        assert engine.evaluate({"score": 0.6}).action == PolicyAction.FLAG
        assert engine.evaluate({"score": 0.1}).action == PolicyAction.ALLOW
