from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mcp_taxonomy import AttackCategory, Confidence, Severity


@dataclass
class PromptArmorEvent:
    """A security event recorded by PromptArmor during request processing.

    Attributes:
        request_id: Unique identifier for the request.
        timestamp: When the event occurred.
        source: IP address or identifier of the client.
        prompt: The text prompt that triggered the event.
        filtered: Whether the prompt was filtered (blocked/flagged).
        action: The action taken (block, flag, allow, sanitize).
        category: Attack category from mcp-taxonomy.
        severity: Severity level from mcp-taxonomy.
        confidence: Confidence level from mcp-taxonomy.
        score: Detection score (0.0 to 1.0).
        matched_rules: Names of matched detection rules.
        metadata: Arbitrary key-value metadata.
        response: The LLM response text, if available.
    """

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
    """Result of a single filter evaluation.

    Attributes:
        allowed: Whether the prompt is allowed through.
        action: The action taken (allow, block, flag, sanitize).
        reason: Human-readable explanation.
        score: Detection score (0.0 to 1.0).
        category: Attack category from mcp-taxonomy.
        severity: Severity level from mcp-taxonomy.
        confidence: Confidence level from mcp-taxonomy.
        details: Additional filter-specific details.
    """

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
    """Configuration for the PromptArmor proxy server.

    Attributes:
        host: Bind address for the server.
        port: Listen port.
        target_url: Upstream LLM API URL to proxy requests to.
        api_key: API key for upstream authentication.
        policy_file: Path to a YAML policy file.
        allowed_models: List of allowed model names (empty = allow all).
        max_prompt_length: Maximum prompt character length.
        rate_limit: Max requests per minute per IP.
        log_level: Logging level (info, debug, warning, error).
        adapter: LLM provider adapter name (openai, anthropic, local, generic).
    """

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
