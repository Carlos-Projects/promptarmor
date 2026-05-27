from pathlib import Path
from typing import Any

import yaml

from promptarmor.policies.engine import PolicyAction, PolicyRule


class YamlPolicyLoader:
    """Loads and validates policy rules from YAML files or strings.

    Supports optional strict mode that raises on malformed rules.
    """

    def __init__(self, strict: bool = True):
        self.strict = strict

    def load(self, path: str) -> list[PolicyRule]:
        """Load policy rules from a YAML file path.

        Resolves the path to prevent directory traversal.
        """
        filepath = Path(path).resolve()
        if not filepath.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        with open(filepath) as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError(f"Empty or invalid YAML: {path}")
        return self._parse_rules(data)

    def loads(self, yaml_string: str) -> list[PolicyRule]:
        """Load policy rules from a YAML string."""
        data = yaml.safe_load(yaml_string)
        if not data:
            raise ValueError("Empty or invalid YAML string")
        return self._parse_rules(data)

    def _parse_rules(self, data: Any) -> list[PolicyRule]:
        """Parse a list of rule dicts from a loaded YAML document."""
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
        """Validate a policy file or YAML string.

        Returns ``(True, message)`` on success or ``(False, error)`` on failure.
        """
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
