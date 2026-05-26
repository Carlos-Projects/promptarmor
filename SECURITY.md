# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in PromptArmor, please report it privately via GitHub's **Security Advisory** feature:

1. Go to https://github.com/Carlos-Projects/promptarmor/security/advisories
2. Click "New advisory"
3. Fill in the details, including steps to reproduce

Do **not** open a public issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Considerations

PromptArmor is a security tool designed to protect LLM APIs. When using it:

- Always run the proxy behind a firewall or VPN in production
- Use HTTPS for upstream connections
- Store API keys in environment variables, not in code
- Regularly update policies based on new attack patterns
- Monitor logs for blocked and flagged events
