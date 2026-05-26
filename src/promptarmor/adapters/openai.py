from collections.abc import AsyncIterator
from typing import Any

import httpx


class OpenAIAdapter:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4",
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
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        return self._client

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "stream": stream,
        }
        body.update(kwargs)
        response = await self.client.post("/chat/completions", json=body)
        response.raise_for_status()
        return response.json()

    async def stream_chat_completion(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        body: dict[str, Any] = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "stream": True,
        }
        body.update(kwargs)
        async with self.client.stream("POST", "/chat/completions", json=body) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    yield {"data": line[6:]}

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
