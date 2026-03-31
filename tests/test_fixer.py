"""Tests for auto-fix engine."""

from __future__ import annotations

import json
from pathlib import Path

from mcpguard.discovery import extract_servers
from mcpguard.engine import load_rules, scan_server
from mcpguard.fixer import can_fix, fix_findings
from mcpguard.models import Finding, Severity


class TestCanFix:
    def test_secret_rules_are_fixable(self) -> None:
        f = Finding(rule_id="MCP01-003", name="test", severity=Severity.CRITICAL)
        assert can_fix(f) is True

    def test_entropy_rule_not_fixable(self) -> None:
        f = Finding(rule_id="MCP01-007", name="test", severity=Severity.HIGH)
        assert can_fix(f) is False

    def test_auth_http_fixable(self) -> None:
        f = Finding(rule_id="MCP07-002", name="test", severity=Severity.HIGH)
        assert can_fix(f) is True

    def test_wildcard_fixable(self) -> None:
        f = Finding(rule_id="MCP02-001", name="test", severity=Severity.CRITICAL)
        assert can_fix(f) is True

    def test_supply_chain_not_fixable(self) -> None:
        f = Finding(rule_id="MCP04-001", name="test", severity=Severity.HIGH)
        assert can_fix(f) is False


class TestFixFindings:
    def test_fixes_hardcoded_secret(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "gh": {
                    "command": "npx",
                    "args": [],
                    "env": {"GITHUB_TOKEN": "ghp_abc123def456ghi789jkl012mno345pqr678"},
                }
            }
        }
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config), encoding="utf-8")

        finding = Finding(
            rule_id="MCP01-003",
            name="Hardcoded GitHub PAT",
            severity=Severity.CRITICAL,
            file_path=str(p),
            server_name="gh",
        )

        fixed, skipped, modified = fix_findings([finding])
        assert fixed == 1
        assert len(modified) == 1

        result = json.loads(p.read_text())
        assert result["mcpServers"]["gh"]["env"]["GITHUB_TOKEN"] == "${GITHUB_TOKEN}"

    def test_fixes_http_to_https(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "api": {
                    "type": "http",
                    "url": "http://api.example.com/mcp",
                }
            }
        }
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config), encoding="utf-8")

        finding = Finding(
            rule_id="MCP07-002",
            name="Plaintext HTTP",
            severity=Severity.HIGH,
            file_path=str(p),
            server_name="api",
        )

        fixed, _, _ = fix_findings([finding])
        assert fixed == 1

        result = json.loads(p.read_text())
        assert result["mcpServers"]["api"]["url"] == "https://api.example.com/mcp"

    def test_does_not_upgrade_localhost_to_https(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "dev": {
                    "type": "http",
                    "url": "http://localhost:3001/mcp",
                }
            }
        }
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config), encoding="utf-8")

        finding = Finding(
            rule_id="MCP07-002",
            name="Plaintext HTTP",
            severity=Severity.HIGH,
            file_path=str(p),
            server_name="dev",
        )

        fixed, skipped, _ = fix_findings([finding])
        assert fixed == 0
        assert skipped == 1

    def test_removes_wildcard_always_allow(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "risky": {
                    "command": "node",
                    "args": ["server.js"],
                    "alwaysAllow": ["*"],
                }
            }
        }
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config), encoding="utf-8")

        finding = Finding(
            rule_id="MCP02-001",
            name="Wildcard",
            severity=Severity.CRITICAL,
            file_path=str(p),
            server_name="risky",
        )

        fixed, _, _ = fix_findings([finding])
        assert fixed == 1

        result = json.loads(p.read_text())
        assert "alwaysAllow" not in result["mcpServers"]["risky"]

    def test_creates_backup(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"gh": {"command": "npx", "args": [], "env": {"TOKEN": "ghp_abc123def456ghi789jkl012mno345pqr678"}}}}
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config), encoding="utf-8")

        finding = Finding(rule_id="MCP01-003", name="t", severity=Severity.CRITICAL, file_path=str(p), server_name="gh")
        fix_findings([finding])

        backup = tmp_path / "mcp.json.mcpguard-backup"
        assert backup.exists()
        original = json.loads(backup.read_text())
        assert original["mcpServers"]["gh"]["env"]["TOKEN"].startswith("ghp_")

    def test_dry_run_does_not_modify(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"gh": {"command": "npx", "args": [], "env": {"TOKEN": "ghp_abc123def456ghi789jkl012mno345pqr678"}}}}
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps(config), encoding="utf-8")
        original_text = p.read_text()

        finding = Finding(rule_id="MCP01-003", name="t", severity=Severity.CRITICAL, file_path=str(p), server_name="gh")
        fixed, _, _ = fix_findings([finding], dry_run=True)

        assert fixed == 1
        assert p.read_text() == original_text  # file unchanged
