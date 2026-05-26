import tempfile
from pathlib import Path

import pytest

from promptarmor.policies.engine import PolicyAction
from promptarmor.policies.yaml_loader import YamlPolicyLoader

SAMPLE_YAML = """
rules:
  - id: rule-1
    name: "Block Critical"
    description: "Block critical injections"
    action: block
    priority: 100
    enabled: true
    conditions:
      score_min: 0.8
      category: prompt_injection

  - id: rule-2
    name: "Flag Medium"
    description: "Flag medium risk"
    action: flag
    priority: 50
    conditions:
      score_min: 0.5
"""


class TestYamlPolicyLoader:
    def setup_method(self):
        self.loader = YamlPolicyLoader()

    def test_loads_valid_yaml(self):
        rules = self.loader.loads(SAMPLE_YAML)
        assert len(rules) == 2
        assert rules[0].id == "rule-1"
        assert rules[0].action == PolicyAction.BLOCK
        assert rules[1].action == PolicyAction.FLAG

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(SAMPLE_YAML)
            path = f.name
        try:
            rules = self.loader.load(path)
            assert len(rules) == 2
        finally:
            Path(path).unlink()

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            self.loader.load("/nonexistent/path.yaml")

    def test_empty_yaml(self):
        with pytest.raises(ValueError):
            self.loader.loads("")

    def test_invalid_rule_structure(self):
        with pytest.raises(ValueError):
            self.loader.loads("rules: [42]")

    def test_validate_valid(self):
        valid, msg = self.loader.validate(SAMPLE_YAML)
        assert valid
        assert "2 rule" in msg

    def test_validate_invalid_path(self):
        valid, msg = self.loader.validate("/nonexistent.yaml")
        assert not valid

    def test_default_values(self):
        minimal = """
rules:
  - name: "Minimal"
"""
        rules = self.loader.loads(minimal)
        assert len(rules) == 1
        assert rules[0].action == PolicyAction.BLOCK
        assert rules[0].enabled is True

    def test_invalid_action(self):
        invalid = """
rules:
  - id: bad-action
    name: "Bad"
    action: invalid_action
"""
        with pytest.raises((ValueError, KeyError)):
            self.loader.loads(invalid)
