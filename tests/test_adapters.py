from promptarmor.adapters.anthropic import AnthropicAdapter
from promptarmor.adapters.generic import GenericHTTPAdapter
from promptarmor.adapters.local_llm import LocalLLMAdapter
from promptarmor.adapters.openai import OpenAIAdapter


class TestOpenAIAdapter:
    def test_init(self):
        adapter = OpenAIAdapter(api_key="sk-test", model="gpt-4")
        assert adapter.api_key == "sk-test"
        assert adapter.model == "gpt-4"
        assert adapter.base_url == "https://api.openai.com/v1"

    def test_client_headers(self):
        adapter = OpenAIAdapter(api_key="sk-test")
        client = adapter.client
        assert client.headers["Authorization"] == "Bearer sk-test"

    def test_close(self):
        adapter = OpenAIAdapter(api_key="sk-test")
        assert adapter._client is None
        adapter.close()

    def test_custom_base_url(self):
        adapter = OpenAIAdapter(api_key="sk-test", base_url="https://custom.example.com/v1")
        assert adapter.base_url == "https://custom.example.com/v1"


class TestAnthropicAdapter:
    def test_init(self):
        adapter = AnthropicAdapter(api_key="sk-ant-test")
        assert adapter.api_key == "sk-ant-test"
        assert adapter.model == "claude-3-opus-20240229"

    def test_client_headers(self):
        adapter = AnthropicAdapter(api_key="sk-ant-test")
        client = adapter.client
        assert client.headers["x-api-key"] == "sk-ant-test"
        assert "anthropic-version" in client.headers

    def test_custom_model(self):
        adapter = AnthropicAdapter(api_key="sk-ant-test", model="claude-3-sonnet-20240229")
        assert adapter.model == "claude-3-sonnet-20240229"


class TestLocalLLMAdapter:
    def test_init(self):
        adapter = LocalLLMAdapter(base_url="http://localhost:8080")
        assert adapter.base_url == "http://localhost:8080"
        assert adapter.model == "local-model"

    def test_custom_timeout(self):
        adapter = LocalLLMAdapter(base_url="http://localhost:8080", timeout=300.0)
        assert adapter.timeout == 300.0


class TestGenericHTTPAdapter:
    def test_init(self):
        adapter = GenericHTTPAdapter(base_url="https://api.example.com")
        assert adapter.base_url == "https://api.example.com"

    def test_custom_headers(self):
        adapter = GenericHTTPAdapter(
            base_url="https://api.example.com",
            headers={"X-Custom": "test"},
        )
        assert adapter.client.headers["X-Custom"] == "test"
