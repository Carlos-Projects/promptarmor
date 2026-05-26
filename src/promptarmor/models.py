from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mcp_taxonomy import AttackCategory, Confidence, Severity


@dataclass
class PromptArmorEvent:
    request_id: str
    timestamp: datetime
    source: str
    prompt: str
    filtered: bool
    action: str
    category: AttackCategory
    severity: Severity
    confidence: Confidence
    score: float
    matched_rules: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    response: str | None = None


@dataclass
class FilterResult:
    allowed: bool
    action: str
    reason: str
    score: float
    category: AttackCategory = AttackCategory.POLICY_VIOLATION
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.NONE
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8100
    target_url: str = ""
    api_key: str = ""
    policy_file: str = ""
    allowed_models: list[str] = field(default_factory=list)
    max_prompt_length: int = 100_000
    rate_limit: int = 100
    log_level: str = "info"
    adapter: str = "generic"
