from datetime import datetime

from mcp_taxonomy import AttackCategory, Confidence, Severity

from promptarmor.models import FilterResult, PromptArmorEvent, ProxyConfig


class TestPromptArmorEvent:
    def test_minimal_event(self):
        event = PromptArmorEvent(
            request_id="req-1",
            timestamp=datetime.now(),
            source="test",
            prompt="hello",
            filtered=False,
            action="allow",
            category=AttackCategory.POLICY_VIOLATION,
            severity=Severity.INFO,
            confidence=Confidence.NONE,
            score=0.0,
        )
        assert event.request_id == "req-1"
        assert event.action == "allow"

    def test_full_event(self):
        event = PromptArmorEvent(
            request_id="req-1",
            timestamp=datetime.now(),
            source="test",
            prompt="hello",
            filtered=True,
            action="block",
            category=AttackCategory.INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            score=0.95,
            matched_rules=["rule-1", "rule-2"],
            metadata={"model": "gpt-4"},
            response="blocked",
        )
        assert len(event.matched_rules) == 2
        assert event.metadata["model"] == "gpt-4"


class TestFilterResult:
    def test_minimal(self):
        result = FilterResult(
            allowed=True,
            action="allow",
            reason="safe",
            score=0.0,
        )
        assert result.allowed

    def test_blocked(self):
        result = FilterResult(
            allowed=False,
            action="block",
            reason="injection detected",
            score=0.9,
            category=AttackCategory.INJECTION,
        )
        assert not result.allowed
        assert result.category.value == "injection"


class TestProxyConfig:
    def test_defaults(self):
        config = ProxyConfig()
        assert config.host == "127.0.0.1"
        assert config.port == 8100
        assert config.max_prompt_length == 100_000
        assert config.rate_limit == 100

    def test_custom(self):
        config = ProxyConfig(
            host="0.0.0.0",
            port=9090,
            target_url="https://api.openai.com/v1",
            api_key="sk-test",
            allowed_models=["gpt-4"],
        )
        assert config.host == "0.0.0.0"
        assert config.allowed_models == ["gpt-4"]
