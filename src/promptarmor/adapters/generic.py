from typing import Any

import httpx


class GenericHTTPAdapter:
    """Generic HTTP adapter for any REST-based LLM endpoint.

    Makes no assumptions about the request/response format beyond
    JSON.  Useful for custom or experimental backends.
    """

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._headers = headers or {}
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            )
        return self._client

    async def post(
        self,
        path: str,
        json_data: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Send a POST request to the generic endpoint."""
        response = await self.client.post(path, json=json_data, **kwargs)
        response.raise_for_status()
        return response.json()

    async def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Send a GET request to the generic endpoint."""
        response = await self.client.get(path, **kwargs)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
