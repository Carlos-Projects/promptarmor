from typing import Any

import httpx

LOCAL_ALLOWED_PARAMS: set[str] = {
    "model",
    "max_tokens",
    "temperature",
    "top_p",
    "stop",
    "stream",
}


class LocalLLMAdapter:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        model: str = "local-model",
        timeout: float = 120.0,
    ):
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
                    "Content-Type": "application/json",
                    "User-Agent": "PromptArmor/0.1.0",
                },
                timeout=self.timeout,
            )
        return self._client

    def _filter_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in kwargs.items() if k in LOCAL_ALLOWED_PARAMS}

    async def generate(
        self,
        prompt: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "prompt": prompt,
            "model": kwargs.get("model", self.model),
        }
        body.update(self._filter_kwargs(kwargs))
        response = await self.client.post("/generate", json=body)
        response.raise_for_status()
        return response.json()

    async def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "messages": messages,
            "model": kwargs.get("model", self.model),
        }
        body.update(self._filter_kwargs(kwargs))
        response = await self.client.post("/v1/chat/completions", json=body)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
