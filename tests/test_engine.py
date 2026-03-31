"""Tests for detection engine and rules."""

from __future__ import annotations

from pathlib import Path

from mcpguard.discovery import extract_servers
from mcpguard.engine import load_rules, scan_server
from mcpguard.models import Severity


class TestLoadRules:
    def test_loads_builtin_rules(self) -> None:
        rules = load_rules()
        assert len(rules) > 0
        assert all("id" in r for r in rules)

    def test_all_rules_have_required_fields(self) -> None:
        rules = load_rules()
        for rule in rules:
            assert "id" in rule, f"Rule missing id: {rule}"
            info = rule.get("info", {})
            assert "name" in info, f"Rule {rule['id']} missing info.name"
            assert "severity" in info, f"Rule {rule['id']} missing info.severity"
            assert info["severity"] in ("critical", "high", "medium", "low", "info")

    def test_all_rules_have_owasp_mapping(self) -> None:
        rules = load_rules()
        for rule in rules:
            info = rule.get("info", {})
            owasp = info.get("owasp", "")
            assert owasp.startswith("MCP"), f"Rule {rule['id']} missing OWASP mapping"


class TestScanSecrets:
    def test_detects_github_pat(self) -> None:
        config = {
            "mcpServers": {
                "gh": {
                    "command": "npx",
                    "args": [],
                    "env": {"TOKEN": "ghp_abc123def456ghi789jkl012mno345pqr678"},
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        rules = load_rules()
        findings = scan_server(servers[0], rules)
        secret_findings = [f for f in findings if f.owasp == "MCP01"]
        assert len(secret_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in secret_findings)

    def test_detects_openai_key(self) -> None:
        config = {
            "mcpServers": {
                "ai": {
                    "command": "node",
                    "args": [],
                    "env": {"OPENAI_API_KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"},
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        assert any(f.rule_id == "MCP01-002" for f in findings)

    def test_ignores_env_var_references(self) -> None:
        config = {
            "mcpServers": {
                "safe": {
                    "command": "npx",
                    "args": [],
                    "env": {"TOKEN": "${GITHUB_TOKEN}"},
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        secret_findings = [f for f in findings if f.owasp == "MCP01"]
        assert len(secret_findings) == 0


class TestScanAuth:
    def test_detects_http_without_auth(self) -> None:
        config = {
            "mcpServers": {
                "api": {
                    "type": "http",
                    "url": "http://api.example.com/mcp",
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        assert any(f.rule_id == "MCP07-001" for f in findings)

    def test_detects_plaintext_http(self) -> None:
        config = {
            "mcpServers": {
                "api": {
                    "type": "http",
                    "url": "http://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer ${TOKEN}"},
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        assert any(f.rule_id == "MCP07-002" for f in findings)

    def test_passes_https_with_auth(self) -> None:
        config = {
            "mcpServers": {
                "api": {
                    "type": "http",
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer ${TOKEN}"},
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        auth_findings = [f for f in findings if f.owasp == "MCP07"]
        assert len(auth_findings) == 0


class TestScanPermissions:
    def test_detects_wildcard_always_allow(self) -> None:
        config = {
            "mcpServers": {
                "risky": {
                    "command": "node",
                    "args": ["server.js"],
                    "alwaysAllow": ["*"],
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        assert any(f.rule_id == "MCP02-001" for f in findings)


class TestScanSupplyChain:
    def test_detects_at_latest(self) -> None:
        config = {
            "mcpServers": {
                "pkg": {
                    "command": "npx",
                    "args": ["-y", "some-mcp-server@latest"],
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        assert any(f.rule_id == "MCP04-001" for f in findings)


class TestScanShadow:
    def test_detects_localhost(self) -> None:
        config = {
            "mcpServers": {
                "dev": {
                    "type": "http",
                    "url": "http://localhost:3001/mcp",
                    "headers": {"Authorization": "Bearer ${T}"},
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        findings = scan_server(servers[0], load_rules())
        assert any(f.rule_id == "MCP09-001" for f in findings)


class TestVulnerableConfig:
    def test_full_vulnerable_scan(self, vulnerable_config: dict) -> None:
        servers = extract_servers("test", Path("/f.json"), vulnerable_config)
        rules = load_rules()
        all_findings = []
        for server in servers:
            all_findings.extend(scan_server(server, rules))

        # Should find multiple issues
        assert len(all_findings) >= 4

        owasp_covered = {f.owasp for f in all_findings}
        assert "MCP01" in owasp_covered  # secrets
        assert "MCP07" in owasp_covered  # auth
        assert "MCP02" in owasp_covered  # permissions

    def test_safe_config_passes(self, safe_config: dict) -> None:
        servers = extract_servers("test", Path("/f.json"), safe_config)
        rules = load_rules()
        all_findings = []
        for server in servers:
            all_findings.extend(scan_server(server, rules))

        critical = [f for f in all_findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0
