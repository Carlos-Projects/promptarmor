from pathlib import Path
from typing import Any

import yaml

from promptarmor.policies.engine import PolicyAction, PolicyRule


class YamlPolicyLoader:
    def __init__(self, strict: bool = True):
        self.strict = strict

    def load(self, path: str) -> list[PolicyRule]:
        filepath = Path(path)
        if not filepath.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        with open(filepath) as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError(f"Empty or invalid YAML: {path}")
        return self._parse_rules(data)

    def loads(self, yaml_string: str) -> list[PolicyRule]:
        data = yaml.safe_load(yaml_string)
        if not data:
            raise ValueError("Empty or invalid YAML string")
        return self._parse_rules(data)

    def _parse_rules(self, data: Any) -> list[PolicyRule]:
        rules_data = data.get("rules", [])
        if not isinstance(rules_data, list):
            raise ValueError("'rules' must be a list")
        rules: list[PolicyRule] = []
        for i, item in enumerate(rules_data):
            if not isinstance(item, dict):
                if self.strict:
                    raise ValueError(f"Rule {i} is not a dict")
                continue
            try:
                rule = PolicyRule(
                    id=item.get("id", f"rule-{i}"),
                    name=item.get("name", f"Rule {i}"),
                    description=item.get("description", ""),
                    action=PolicyAction(item.get("action", "block")),
                    priority=item.get("priority", 0),
                    enabled=item.get("enabled", True),
                    conditions=item.get("conditions", {}),
                    metadata=item.get("metadata", {}),
                )
                rules.append(rule)
            except (ValueError, KeyError) as e:
                if self.strict:
                    raise ValueError(f"Invalid rule {i}: {e}")
        return rules

    def validate(self, path_or_yaml: str) -> tuple[bool, str]:
        try:
            rules = self.load(path_or_yaml)
            return True, f"Valid: {len(rules)} rule(s) loaded"
        except (FileNotFoundError, OSError):
            try:
                rules = self.loads(path_or_yaml)
                return True, f"Valid: {len(rules)} rule(s) loaded"
            except Exception as e:
                return False, str(e)
        except Exception as e:
            return False, str(e)
