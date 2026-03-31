<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/loplop-h/mcpguard/master/docs/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/loplop-h/mcpguard/master/docs/logo-light.svg">
    <img alt="mcpguard" src="https://raw.githubusercontent.com/loplop-h/mcpguard/master/docs/logo-light.svg" width="450">
  </picture>
</p>

<p align="center"><strong>Find security vulnerabilities in your MCP server configs before attackers do.</strong></p>
<p align="center">Maps every finding to the OWASP MCP Top 10. Zero config. Runs locally.</p>

<p align="center">
  <a href="https://pypi.org/project/guardmcp/"><img src="https://img.shields.io/pypi/v/guardmcp?style=flat-square" alt="PyPI"></a>
  <a href="https://pypi.org/project/guardmcp/"><img src="https://img.shields.io/pypi/pyversions/guardmcp?style=flat-square" alt="Python"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/loplop-h/mcpguard/stargazers"><img src="https://img.shields.io/github/stars/loplop-h/mcpguard?style=flat-square" alt="Stars"></a>
  <a href="https://owasp.org/www-project-mcp-top-10/"><img src="https://img.shields.io/badge/OWASP-MCP%20Top%2010-orange?style=flat-square" alt="OWASP"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/loplop-h/mcpguard/master/docs/scan-screenshot.png?v=3" alt="mcpguard scan output" width="650">
</p>

## Quick Start

```bash
pip install guardmcp
mcpguard scan
```

That's it. mcpguard auto-detects MCP configs from Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf. No API keys, no accounts, everything runs locally.

## What It Scans For

mcpguard checks your MCP server configurations against the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/):

| | Risk | What mcpguard detects |
|---|------|----------------------|
| Y | **MCP01** Token & Secret Exposure | Hardcoded API keys (AWS, OpenAI, GitHub, Anthropic, Stripe), high-entropy secrets, JWT tokens, live secret verification |
| Y | **MCP02** Privilege Escalation | Wildcard `alwaysAllow`, overpermissioned tool scopes |
| Y | **MCP03** Tool Poisoning | 14 injection patterns in tool descriptions, suspicious names, long descriptions, tool shadowing, rug pull detection |
| Y | **MCP04** Supply Chain Attacks | Unpinned `@latest` versions, missing version locks |
| Y | **MCP05** Command Injection | Shell metacharacters, dangerous commands, missing input schemas |
| Y | **MCP06** Intent Subversion | SSRF-prone URLs (cloud metadata, private IPs) |
| Y | **MCP07** Missing Authentication | HTTP servers without auth headers, plaintext HTTP transport |
| Y | **MCP08** No Audit Logging | Unsafe shell execution, pipe/redirect in args |
| Y | **MCP09** Shadow Servers | Localhost/dev URLs, unregistered servers |
| Y | **MCP10** Context Over-Sharing | Docker host network, sensitive volume mounts, no rate limiting |

## Features

- **Zero config** -- auto-discovers configs from 5 MCP clients
- **OWASP mapped** -- every finding links to OWASP MCP Top 10
- **16 detection rules** -- secrets, auth, permissions, supply chain, injection, shadow servers
- **Entropy-based secret detection** -- catches secrets that don't match known patterns
- **Auto-fix** -- `mcpguard fix` replaces hardcoded secrets with `${VAR}` references
- **Custom rules** -- add your own YAML detection rules
- **SARIF output** -- integrates with GitHub Security tab
- **GitHub Action** -- drop-in CI/CD security gate
- **Pre-commit hook** -- catch issues before they're committed
- **No network** -- everything runs locally, no API calls

## Usage

```bash
# Scan all auto-detected configs
mcpguard scan

# Scan a specific config file
mcpguard scan --path /path/to/mcp.json

# Auto-fix hardcoded secrets, HTTP URLs, wildcard permissions
mcpguard fix

# Preview fixes without modifying files
mcpguard fix --dry-run

# JSON output for CI/CD
mcpguard scan --format json

# SARIF output for GitHub Security tab
mcpguard scan --format sarif -o results.sarif

# Only show critical and high findings
mcpguard scan --severity high

# Connect to servers and inspect tool definitions
mcpguard inspect

# Verify detected secrets are live (makes read-only API calls)
mcpguard scan --verify

# Quick pass/fail check (exit code only)
mcpguard check

# Add custom detection rules
mcpguard scan --rules-dir ./my-rules/
```

## Auto-Fix

mcpguard can automatically fix common security issues:

```bash
mcpguard fix
```

What it fixes:
- Replaces hardcoded API keys with `${VAR_NAME}` environment variable references
- Upgrades `http://` URLs to `https://`
- Removes wildcard `alwaysAllow: ["*"]`
- Creates a `.mcpguard-backup` before modifying any file

## Supported Clients

| Client | Config Location |
|--------|----------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json`, `.mcp.json` |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json` |
| VS Code | `~/.config/Code/User/mcp.json`, `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

## Custom Rules

mcpguard uses YAML detection rules. Add your own:

```yaml
id: CUSTOM-001
info:
  name: Internal API Key Pattern
  severity: critical
  owasp: MCP01
  description: Detects internal API keys
  remediation: Use vault references
  cwe: CWE-798
detection:
  target: config
  scope: env_values
  match:
    type: regex
    patterns:
      - 'internal_[a-z0-9]{32}'
```

```bash
mcpguard scan --rules-dir ./my-rules/
```

## GitHub Action

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  mcpguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: loplop-h/mcpguard@v1
```

Or manually:

```yaml
      - run: pip install guardmcp
      - run: mcpguard scan --format sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/loplop-h/mcpguard
    rev: v0.1.0
    hooks:
      - id: mcpguard
```

## How It Compares

| Feature | mcpguard | mcp-scan | Tencent AI-Infra-Guard | Cisco mcp-scanner |
|---------|----------|----------|------------------------|-------------------|
| Zero-config CLI | Y | Y | N (Docker/web) | N (API key) |
| Config scanning | Y | Y | Y | Y |
| Server inspection | Y | Y | Y | N |
| Tool poisoning detection | Y (14 patterns) | Y | Partial | N |
| Rug pull detection | Y (hash pinning) | Y | N | N |
| Auto-fix (`fix`) | **Y** | N | N | N |
| OWASP MCP Top 10 mapping | **Y (10/10)** | N | N | N |
| Secret verification | **Y** (GitHub, OpenAI, Anthropic, Stripe) | N | N | N |
| SARIF output | **Y** | N | N | N |
| GitHub Action | **Y** | N | N | N |
| Pre-commit hook | **Y** | N | N | N |
| Custom YAML rules | **Y** | N | N | N |
| Entropy-based detection | **Y** | N | N | N |

## Privacy

- All data stays on your machine
- No telemetry, no tracking
- `scan` reads config files only (no network)
- `inspect` connects to local stdio servers only (never sends data externally)
- `--verify` makes read-only API calls to check if secrets are live
- Open source, MIT licensed

## Contributing

```bash
git clone https://github.com/loplop-h/mcpguard.git
cd mcpguard
pip install -e ".[dev]"
pytest
```

Add detection rules in `src/mcpguard/rules/` using the YAML schema above.

## License

MIT
