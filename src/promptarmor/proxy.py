from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import httpx
from mcp_taxonomy import AttackCategory, Confidence, Severity
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from promptarmor.filters.adaptive_defense import AdaptiveDefense
from promptarmor.filters.context_sanitizer import ContextSanitizer
from promptarmor.filters.injection_detector import InjectionDetector
from promptarmor.filters.latent_whitelist import LatentWhitelist
from promptarmor.filters.output_validator import OutputValidator
from promptarmor.filters.self_reflection import SelfReflectionGuard
from promptarmor.models import PromptArmorEvent, ProxyConfig
from promptarmor.policies.engine import PolicyEngine
from promptarmor.reporters.console import ConsoleReporter

logger = logging.getLogger("promptarmor.proxy")

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.CERTAIN: 5,
    Confidence.HIGH: 4,
    Confidence.MEDIUM: 3,
    Confidence.LOW: 2,
    Confidence.NONE: 1,
}
_REVERSE_SEVERITY = {v: k for k, v in _SEVERITY_ORDER.items()}
_REVERSE_CONFIDENCE = {v: k for k, v in _CONFIDENCE_ORDER.items()}
_USER_AGENT = "PromptArmor/0.1.0"


def _max_severity(*sev: Severity) -> Severity:
    """Return the highest severity from a sequence."""
    return _REVERSE_SEVERITY[max(_SEVERITY_ORDER[s] for s in sev)]


def _max_confidence(*con: Confidence) -> Confidence:
    """Return the highest confidence from a sequence."""
    return _REVERSE_CONFIDENCE[max(_CONFIDENCE_ORDER[c] for c in con)]


ALLOWED_CHAT_FIELDS: set[str] = {
    "model",
    "messages",
    "max_tokens",
    "temperature",
    "stop",
    "stream",
    "top_p",
    "frequency_penalty",
    "presence_penalty",
    "n",
    "user",
    "tools",
    "tool_choice",
    "response_format",
    "seed",
}
ALLOWED_COMPLETION_FIELDS: set[str] = {
    "model",
    "prompt",
    "max_tokens",
    "temperature",
    "stop",
    "stream",
    "top_p",
    "frequency_penalty",
    "presence_penalty",
    "n",
    "user",
    "suffix",
    "logprobs",
    "echo",
    "seed",
}
ALLOWED_MESSAGE_FIELDS: set[str] = {"role", "content", "name", "tool_call_id", "tool_calls"}
_MAX_REQUEST_BYTES = 1_048_576


def _sanitize_body(body: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    """Strip unknown fields from request body to prevent mass assignment."""
    sanitized = {k: v for k, v in body.items() if k in allowed}
    if "messages" in sanitized:
        sanitized["messages"] = [
            {k: v for k, v in msg.items() if k in ALLOWED_MESSAGE_FIELDS} for msg in sanitized["messages"]
        ]
    return sanitized


def _validate_response_schema(response: dict[str, Any]) -> bool:
    """Ensure the upstream response matches an expected schema structure."""
    if "choices" in response and isinstance(response["choices"], list):
        return True
    if "completion" in response or "content" in response:
        return True
    return False


class AuthMiddleware(BaseHTTPMiddleware):
    """Validates Bearer token on every request (except /health).

    Reads the API key from ``app.state.config.api_key``. Requests missing
    or mismatched tokens receive a 401 response.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        config = request.app.state.config
        if request.url.path == "/health":
            return await call_next(request)
        if config.api_key:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer ") or auth_header.removeprefix("Bearer ") != config.api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "unauthorized", "message": "Invalid or missing API key"},
                )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security-related HTTP headers to every response."""

    HEADERS: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for key, value in self.HEADERS.items():
            response.headers[key] = value
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter per IP with an async-safe lock.

    Tracks request timestamps per IP and rejects requests that exceed
    ``max_requests`` within ``window_seconds``.
    """

    def __init__(self, app: Any, max_requests: int = 100, window_seconds: int = 60) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path == "/health":
            return await call_next(request)
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        cutoff = now - self.window_seconds
        async with self._lock:
            window = [t for t in self._buckets[ip] if t > cutoff]
            self._buckets[ip] = window
            if len(window) >= self.max_requests:
                logger.warning("Rate limit exceeded for %s", ip)
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limited", "message": "Too many requests"},
                )
            self._buckets[ip].append(now)
        return await call_next(request)


@asynccontextmanager
async def _lifespan(app: Starlette) -> AsyncGenerator[None, None]:
    """Startup/shutdown lifecycle handler registered with Starlette."""
    proxy: PromptArmorProxy = app.state.proxy
    await proxy.startup()
    yield
    await proxy.shutdown()


class PromptArmorProxy:
    """Core proxy server that interposes between clients and LLM APIs.

    Applies security filters (injection detection, self-reflection,
    context sanitization, output validation), enforces policies, and
    optionally forwards sanitized requests to the configured upstream.
    """

    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.injection_detector = InjectionDetector()
        self.self_reflection = SelfReflectionGuard()
        self.latent_whitelist = LatentWhitelist()
        self.context_sanitizer = ContextSanitizer()
        self.output_validator = OutputValidator()
        self.adaptive_defense = AdaptiveDefense()
        self.policy_engine = PolicyEngine()
        self.reporter = ConsoleReporter()

        self._http_client = httpx.AsyncClient(timeout=60.0)
        self._events: list[PromptArmorEvent] = []

        self.app = Starlette(
            routes=[
                Route("/v1/chat/completions", self.handle_chat_completion, methods=["POST"]),
                Route("/v1/completions", self.handle_completion, methods=["POST"]),
                Route("/health", self.handle_health, methods=["GET"]),
                Route("/{path:path}", self.handle_catch_all),
            ],
            middleware=[
                Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
                Middleware(SecurityHeadersMiddleware),
                Middleware(AuthMiddleware),
                Middleware(RateLimitMiddleware, max_requests=config.rate_limit),
            ],
            lifespan=_lifespan,
        )
        self.app.state.config = config
        self.app.state.proxy = self
        if config.target_url and not config.api_key:
            logger.warning("Proxy configured with target URL but no API key")

    async def _parse_body(self, request: Request) -> dict[str, Any] | None:
        """Parse the request JSON body, enforcing the 1 MB size limit.

        Returns ``None`` if the body is too large or contains invalid JSON.
        """
        content_length = request.headers.get("content-length", "0")
        if content_length.isdigit() and int(content_length) > _MAX_REQUEST_BYTES:
            return None
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            return None
        return body

    def _run_filters_sync(self, prompt: str) -> dict[str, Any]:
        """Synchronously run all detection filters and the policy engine.

        Offloaded to a thread via ``run_in_executor`` to avoid blocking
        the async event loop.
        """
        injection_result = self.injection_detector.detect(prompt)
        reflection_result = self.self_reflection.analyze(prompt)
        sanitization = self.context_sanitizer.sanitize(prompt)

        max_score = max(injection_result.score, reflection_result.score)
        categories: list[str] = []
        if injection_result.detected:
            categories.append(injection_result.category.value)
        if reflection_result.detected:
            categories.append(reflection_result.category.value)

        severity_enum = _max_severity(injection_result.severity, reflection_result.severity)
        confidence_enum = _max_confidence(injection_result.confidence, reflection_result.confidence)
        category_enum = AttackCategory(categories[0]) if categories else AttackCategory.POLICY_VIOLATION

        if max_score >= 0.8:
            action = "block"
        elif max_score >= 0.5:
            action = "flag"
        else:
            action = "allow"

        result: dict[str, Any] = {
            "allowed": action == "allow",
            "action": action,
            "score": max_score,
            "category": category_enum,
            "severity": severity_enum,
            "confidence": confidence_enum,
            "sanitized_prompt": sanitization.cleaned_text,
            "matched_rules": injection_result.matched_patterns + reflection_result.triggers,
        }

        for pattern in injection_result.matched_patterns:
            self.adaptive_defense.record_event(pattern, injection_result.severity)
        for trigger in reflection_result.triggers:
            self.adaptive_defense.record_event(trigger, reflection_result.severity)

        policy_context = {"score": max_score, "category": category_enum.value, "source": "proxy"}
        policy_result = self.policy_engine.evaluate(policy_context)
        if policy_result.matched and policy_result.action.value != "allow":
            result["action"] = policy_result.action.value
            result["allowed"] = policy_result.action.value == "allow"
            result["reason"] = policy_result.reason

        return result

    async def _run_filters(self, prompt: str) -> dict[str, Any]:
        """Run all detection filters off the event loop via a thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_filters_sync, prompt)

    async def _proxy_request(self, body: dict[str, Any]) -> dict[str, Any]:
        """Forward a sanitized request body to the upstream LLM API."""
        target = self.config.target_url
        if not target:
            return {"choices": [{"message": {"content": "Mock response: proxy not configured"}}]}
        if not target.startswith(("https://", "http://")):
            raise httpx.HTTPError("Invalid target URL scheme")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        response = await self._http_client.post(target, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    async def _proxy_stream(self, body: dict[str, Any]) -> AsyncGenerator[bytes, None]:
        """Stream an upstream SSE response chunk by chunk."""
        target = self.config.target_url
        if not target:
            yield b'data: {"error": "no target configured"}\n\n'
            return
        headers = {
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        body["stream"] = True
        async with self._http_client.stream("POST", target, json=body, headers=headers) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes():
                yield chunk

    def _build_event(
        self, request: Request, prompt: str, result: dict[str, Any], body: dict[str, Any] | None = None
    ) -> PromptArmorEvent:
        """Construct a ``PromptArmorEvent`` from the request and filter result."""
        return PromptArmorEvent(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            source=request.client.host if request.client else "unknown",
            prompt=prompt,
            filtered=not result["allowed"],
            action=result["action"],
            category=result["category"],
            severity=result["severity"],
            confidence=result["confidence"],
            score=result["score"],
            matched_rules=result.get("matched_rules", []),
            metadata={"model": body.get("model", "")} if body else {},
        )

    def _extract_user_prompt(self, messages: list[dict[str, str]]) -> str:
        """Extract the most recent user message content from a messages list."""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                return msg.get("content", "")
        return messages[-1].get("content", "") if messages else ""

    def _update_messages(self, messages: list[dict[str, str]], sanitized: str) -> list[dict[str, str]]:
        """Replace the last user message content with a sanitized version."""
        updated = list(messages)
        for i in range(len(updated) - 1, -1, -1):
            if updated[i].get("role") == "user":
                updated[i]["content"] = sanitized
                break
        return updated

    async def handle_stream_chat(self, request: Request) -> Response:
        """Handle a streaming chat completions request (SSE).

        Returns a ``StreamingResponse`` that proxies the upstream SSE stream
        chunk by chunk.
        """
        body = await self._parse_body(request)
        if body is None:
            return JSONResponse(status_code=400, content={"error": "bad_request", "message": "Invalid body"})
        if not body.get("stream"):
            return await self.handle_chat_completion(request)
        body = _sanitize_body(body, ALLOWED_CHAT_FIELDS)
        messages = body.get("messages", [])
        user_prompt = self._extract_user_prompt(messages)
        result = await self._run_filters(user_prompt)
        if result["action"] == "block":
            return JSONResponse(status_code=403, content={"error": "blocked"})
        return StreamingResponse(
            self._proxy_stream(body),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    async def handle_chat_completion(self, request: Request) -> Response:
        """Handle a non-streaming chat completions request.

        Parses the body, runs detection filters, records a ``PromptArmorEvent``,
        optionally sanitizes the prompt, proxies to the upstream, and validates
        the response before returning it to the client.
        """
        body = await self._parse_body(request)
        if body is None:
            return JSONResponse(
                status_code=400,
                content={"error": "bad_request", "message": "Invalid or too large request body"},
            )
        if body.get("stream"):
            return await self.handle_stream_chat(request)
        body = _sanitize_body(body, ALLOWED_CHAT_FIELDS)
        messages = body.get("messages", [])
        user_prompt = self._extract_user_prompt(messages)

        result = await self._run_filters(user_prompt)
        event = self._build_event(request, user_prompt, result, body)
        self._events.append(event)
        self.reporter.report_event(event)

        if result["action"] == "block":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "blocked",
                    "message": "Prompt blocked by PromptArmor",
                    "request_id": event.request_id,
                    "reason": result.get("reason", "security policy violation"),
                },
            )

        sanitized_prompt = result.get("sanitized_prompt", user_prompt)
        if sanitized_prompt != user_prompt:
            body["messages"] = self._update_messages(messages, sanitized_prompt)

        try:
            response = await self._proxy_request(body)
            if not _validate_response_schema(response):
                logger.warning("Upstream response has unexpected schema")
                return JSONResponse(
                    status_code=502,
                    content={"error": "bad_upstream", "message": "Unexpected response format from upstream"},
                )
            response_text = str(response.get("choices", [{}])[0].get("message", {}).get("content", ""))
            validation = self.output_validator.validate(response_text)
            if not validation.valid:
                event.response = response_text
                if result["action"] != "flag":
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "blocked",
                            "message": "LLM response blocked by PromptArmor",
                            "request_id": event.request_id,
                            "reason": "output validation failed",
                        },
                    )
            return JSONResponse(response)
        except httpx.HTTPError:
            logger.warning("Upstream request failed", exc_info=True)
            return JSONResponse(
                status_code=502,
                content={"error": "upstream_error", "message": "Upstream LLM request failed"},
            )

    async def handle_completion(self, request: Request) -> Response:
        """Handle a legacy completions endpoint request."""
        body = await self._parse_body(request)
        if body is None:
            return JSONResponse(
                status_code=400,
                content={"error": "bad_request", "message": "Invalid or too large request body"},
            )
        body = _sanitize_body(body, ALLOWED_COMPLETION_FIELDS)
        prompt = body.get("prompt", "")

        result = await self._run_filters(prompt)
        event = self._build_event(request, prompt, result)
        self._events.append(event)
        self.reporter.report_event(event)

        if result["action"] == "block":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "blocked",
                    "message": "Prompt blocked by PromptArmor",
                    "request_id": event.request_id,
                },
            )

        try:
            response = await self._proxy_request(body)
            return JSONResponse(response)
        except httpx.HTTPError:
            logger.warning("Upstream request failed", exc_info=True)
            return JSONResponse(
                status_code=502,
                content={"error": "upstream_error", "message": "Upstream LLM request failed"},
            )

    async def handle_health(self, request: Request) -> Response:
        """Health check endpoint — returns service status."""
        return JSONResponse({"status": "ok", "service": "promptarmor"})

    async def handle_catch_all(self, request: Request, path: str = "") -> Response:
        """Catch-all handler for undefined routes — returns 404."""
        return JSONResponse(status_code=404, content={"error": "not_found"})

    async def startup(self) -> None:
        """Lifecycle hook called when the ASGI server starts."""
        logger.info("PromptArmor proxy starting on %s:%s", self.config.host, self.config.port)

    async def shutdown(self) -> None:
        """Lifecycle hook called when the ASGI server stops.

        Closes the HTTP client to release connections.
        """
        await self._http_client.aclose()
        logger.info("PromptArmor proxy shut down")


def create_proxy(config: ProxyConfig) -> Starlette:
    """Convenience factory — builds a ``PromptArmorProxy`` and returns its
    Starlette ASGI app."""
    proxy = PromptArmorProxy(config)
    return proxy.app
