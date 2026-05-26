from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

import httpx
from mcp_taxonomy import AttackCategory, Confidence, Severity
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
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

_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_CONFIDENCE_ORDER = {
    Confidence.CERTAIN: 5,
    Confidence.HIGH: 4,
    Confidence.MEDIUM: 3,
    Confidence.LOW: 2,
    Confidence.NONE: 1,
}

_REVERSE_SEVERITY = {v: k for k, v in _SEVERITY_ORDER.items()}
_REVERSE_CONFIDENCE = {v: k for k, v in _CONFIDENCE_ORDER.items()}


def _max_severity(*sev: Severity) -> Severity:
    return _REVERSE_SEVERITY[max(_SEVERITY_ORDER[s] for s in sev)]


def _max_confidence(*con: Confidence) -> Confidence:
    return _REVERSE_CONFIDENCE[max(_CONFIDENCE_ORDER[c] for c in con)]


logger = logging.getLogger("promptarmor.proxy")


class PromptArmorProxy:
    def __init__(self, config: ProxyConfig):
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
            ]
        )

    async def handle_chat_completion(self, request: Request) -> Response:
        body = await request.json()
        messages = body.get("messages", [])
        user_prompt = self._extract_user_prompt(messages)

        result = self._run_filters(user_prompt)

        event = PromptArmorEvent(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            source=request.client.host if request.client else "unknown",
            prompt=user_prompt,
            filtered=not result["allowed"],
            action=result["action"],
            category=result["category"],
            severity=result["severity"],
            confidence=result["confidence"],
            score=result["score"],
            matched_rules=result.get("matched_rules", []),
            metadata={"model": body.get("model", "")},
        )

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
        except httpx.HTTPError as e:
            logger.error(f"Upstream request failed: {e}")
            return JSONResponse(
                status_code=502,
                content={"error": "upstream_error", "message": str(e)},
            )

    async def handle_completion(self, request: Request) -> Response:
        body = await request.json()
        prompt = body.get("prompt", "")

        result = self._run_filters(prompt)

        event = PromptArmorEvent(
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
        )

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
        except httpx.HTTPError as e:
            return JSONResponse(
                status_code=502,
                content={"error": "upstream_error", "message": str(e)},
            )

    async def handle_health(self, request: Request) -> Response:
        return JSONResponse({"status": "ok", "service": "promptarmor"})

    async def handle_catch_all(self, request: Request, path: str = "") -> Response:
        return JSONResponse(
            status_code=404,
            content={"error": "not_found", "message": f"Unknown endpoint: {request.url.path}"},
        )

    def _run_filters(self, prompt: str) -> dict[str, Any]:
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

        policy_context = {
            "score": max_score,
            "category": category_enum.value,
            "source": "proxy",
        }
        policy_result = self.policy_engine.evaluate(policy_context)
        if policy_result.matched and policy_result.action.value != "allow":
            result["action"] = policy_result.action.value
            result["allowed"] = policy_result.action.value == "allow"
            result["reason"] = policy_result.reason

        return result

    async def _proxy_request(self, body: dict[str, Any]) -> dict[str, Any]:
        target = self.config.target_url
        if not target:
            return {"choices": [{"message": {"content": "Mock response: proxy not configured"}}]}
        api_key = self.config.api_key
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        response = await self._http_client.post(target, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    def _extract_user_prompt(self, messages: list[dict[str, str]]) -> str:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                return msg.get("content", "")
        return messages[-1].get("content", "") if messages else ""

    def _update_messages(self, messages: list[dict[str, str]], sanitized: str) -> list[dict[str, str]]:
        updated = list(messages)
        for i in range(len(updated) - 1, -1, -1):
            if updated[i].get("role") == "user":
                updated[i]["content"] = sanitized
                break
        return updated

    async def startup(self) -> None:
        logger.info(f"PromptArmor proxy starting on {self.config.host}:{self.config.port}")

    async def shutdown(self) -> None:
        await self._http_client.aclose()
        logger.info("PromptArmor proxy shut down")


def create_proxy(config: ProxyConfig) -> Starlette:
    proxy = PromptArmorProxy(config)
    return proxy.app
