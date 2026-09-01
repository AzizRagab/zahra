# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities privately so they can be fixed before disclosure:

- **Preferred:** [GitHub Private Vulnerability Reporting](https://github.com/amshararou/zahra/security/advisories/new)
- **Fallback:** open a security advisory via the repository's security tab.

When reporting, include:

1. The component affected (ZAHRA core, Pentest-Swarm-AI, or OmniRoute).
2. Steps to reproduce (OS, versions, commands).
3. Impact and any proof-of-concept (no destructive payloads).

We aim to acknowledge reports within 5 business days and to provide a fix
timeline. Please give us a reasonable window before public disclosure.

## Supported Versions

| Version | Supported |
|---|---|
| `2.0.x` (current) | ✅ |
| `< 2.0` | ❌ |

## Responsible Use

ZAHRA is an **offensive-security tool**. It is designed exclusively for
**authorized** penetration testing, security research, education, CTF
competitions, and bug-bounty programs with permission.

- ✅ Authorized engagements only.
- ❌ Unauthorized access or malicious use is prohibited.

Operators are solely responsible for ensuring they have explicit authorization
for every target they use this tool against. See the README's *Responsible Use*
section.

## Operational Security

- API keys and LLM credentials are read from environment variables or local
  config only — never commit secrets (see `.gitignore`).
- The web dashboard binds to localhost by default. When exposing it, use a
  reverse proxy with TLS and authentication.
- Review findings before acting on them; automated output should be validated
  by a human operator.
