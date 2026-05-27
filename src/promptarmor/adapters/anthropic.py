from collections.abc import AsyncIterator
from typing import Any

import httpx

ANTHROPIC_ALLOWED_PARAMS: set[str] = {
    "model",
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "stop_sequences",
    "metadata",
    "stream",
}


class AnthropicAdapter:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.anthropic.com/v1",
        model: str = "claude-3-opus-20240229",
        timeout: float = 60.0,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                    "User-Agent": "PromptArmor/0.1.0",
                },
                timeout=self.timeout,
            )
        return self._client

    def _filter_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in kwargs.items() if k in ANTHROPIC_ALLOWED_PARAMS}

    async def messages(
        self,
        messages: list[dict[str, str]],
        system: str | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "stream": stream,
        }
        if system:
            body["system"] = system
        body.update(self._filter_kwargs(kwargs))
        response = await self.client.post("/messages", json=body)
        response.raise_for_status()
        return response.json()

    async def stream_messages(
        self,
        messages: list[dict[str, str]],
        system: str | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        body: dict[str, Any] = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "stream": True,
        }
        if system:
            body["system"] = system
        body.update(self._filter_kwargs(kwargs))
        async with self.client.stream("POST", "/messages", json=body) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    yield {"data": line[6:]}

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
