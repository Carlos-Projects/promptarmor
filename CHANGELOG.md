# Changelog

## v0.1.0 (2025-05-26)

- Initial release
- CLI: `promptarmor serve / test / policy / report`
- Proxy: auth, rate limiting, security headers, body sanitizer, SSL/TLS
- 5 detection filters: InjectionDetector, SelfReflectionGuard, LatentWhitelist, ContextSanitizer, OutputValidator
- AdaptiveDefense: learns from detection patterns, adjusts thresholds
- Policy engine with YAML loader and MCPGuard generator
- 4 LLM adapters: OpenAI, Anthropic, LocalLLM, GenericHTTP
- 3 reporters: Console (Rich), JSON, HTML (Jinja2)
- Models with mcp-taxonomy classification (AttackCategory, Severity, Confidence)
- Security utilities (crypto, SSRF prevention, path traversal protection)
- Docker support (Dockerfile + docker-compose.yml)
- GitHub Actions CI (matrix 3.11-3.13) + PyPI publisher (Trusted Publishing)
- Community files: CHANGELOG, CODE_OF_CONDUCT, CONTRIBUTING, SECURITY
- Issue/PR templates
- 198 tests, 84%+ coverage, ruff 0 errors, mypy 0 errors
