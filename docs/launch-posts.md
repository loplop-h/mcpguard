# Launch Posts

## X / Twitter (thread)

**Tweet 1:**

I scanned my own MCP configs and found 13 security issues. Hardcoded API keys, servers without auth, unpinned packages.

I built mcpguard -- an open-source scanner that checks your MCP configs against all 10 OWASP MCP Top 10 risks.

pip install mcpguard
mcpguard scan

**Tweet 2 (reply):**

What makes it different from mcp-scan:

- Auto-fix: `mcpguard fix` replaces hardcoded secrets with ${VAR} references
- Connects to servers and detects tool poisoning (14 injection patterns)
- Rug pull detection (hashes tool definitions, alerts on changes)
- SARIF output for GitHub Security tab
- 10/10 OWASP coverage

github.com/loplop-h/mcpguard

---

## Reddit r/ClaudeAI

**Title:** I built an open-source security scanner for MCP configs -- found 13 issues in my own setup

**Body:**

I was curious how secure my MCP server configurations actually were, so I built a scanner. Turns out my Claude Code config had hardcoded GitHub PATs, servers running over plaintext HTTP, and packages with unpinned versions.

**What mcpguard does:**

- `mcpguard scan` -- auto-detects configs from Claude Desktop, Claude Code, Cursor, VS Code, Windsurf. Checks for secrets, missing auth, injection, supply chain risks.
- `mcpguard inspect` -- connects to your MCP servers, lists their tools, and scans descriptions for tool poisoning patterns (found real injection patterns in Playwright's MCP server)
- `mcpguard fix` -- auto-replaces hardcoded secrets with `${VAR}` environment variable references. No other MCP scanner does this.
- Rug pull detection -- hashes every tool definition and alerts you when a server silently changes its tools

Maps every finding to the OWASP MCP Top 10 (10/10 coverage). No other tool covers all 10.

Two commands:

    pip install mcpguard
    mcpguard scan

Repo: https://github.com/loplop-h/mcpguard

29 detection rules, 61 tests, MIT licensed. Zero external services, everything runs locally.

---

## Reddit r/netsec

**Title:** mcpguard: MCP security scanner with 10/10 OWASP MCP Top 10 coverage, tool poisoning detection, and auto-fix

**Body:**

Open-source CLI scanner for Model Context Protocol server configurations. Covers all 10 OWASP MCP Top 10 risks.

Key capabilities:
- Static config analysis: hardcoded secrets (AWS, OpenAI, GitHub, Anthropic, Stripe), missing auth, plaintext HTTP, supply chain (unpinned versions), SSRF-prone URLs, dangerous commands
- Dynamic server inspection: connects to stdio servers, lists tools, scans descriptions for 14 injection patterns (prompt injection, data exfiltration, role injection)
- Rug pull detection: SHA-256 hashes tool definitions, alerts on silent changes between scans
- Auto-remediation: `mcpguard fix` replaces hardcoded secrets with env var references, upgrades HTTP to HTTPS, removes wildcard alwaysAllow
- Secret verification: checks if detected secrets are actually live (GitHub, OpenAI, Anthropic, Stripe APIs)
- SARIF v2.1.0 output for GitHub Security tab, GitHub Action, pre-commit hook

Comparison vs existing tools:
- mcp-scan (2k stars): no auto-fix, no OWASP mapping, no SARIF, no GitHub Action
- Tencent AI-Infra-Guard (3.3k stars): web platform, not a CLI
- Cisco mcp-scanner: requires API keys

Python, Click + Rich, MIT licensed. 29 YAML detection rules, 61 tests.

https://github.com/loplop-h/mcpguard

---

## LinkedIn

I scanned my own MCP server configurations and found 13 security issues.

Hardcoded API keys. Servers without authentication. Unpinned package versions. Plaintext HTTP transport.

These are the same patterns that led to 30+ CVEs in the MCP ecosystem in the first 60 days of 2026.

So I built mcpguard -- an open-source security scanner for MCP server configurations.

What it does:
- Scans configs from Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf
- Covers all 10 OWASP MCP Top 10 risks (the only tool that does)
- Connects to servers and detects tool poisoning in tool descriptions
- Auto-fixes hardcoded secrets by replacing them with ${VAR} references
- Detects rug pull attacks by hashing tool definitions between scans

Two commands to start:
pip install mcpguard
mcpguard scan

No API keys. No external services. Everything runs locally. 29 detection rules. MIT licensed.

Repo: https://github.com/loplop-h/mcpguard
PyPI: https://pypi.org/project/mcpguard/

If you use Claude Code, Cursor, or any MCP-enabled tool -- scan your configs. You might be surprised.

#MCP #Security #ClaudeCode #OpenSource #Python #OWASP #DevTools #AI
