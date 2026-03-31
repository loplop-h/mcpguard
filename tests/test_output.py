"""Tests for output formatting (JSON, SARIF)."""

from __future__ import annotations

import json

from mcpguard.models import Finding, ScanResult, Severity
from mcpguard.printer import format_json, format_sarif


def _make_result() -> ScanResult:
    return ScanResult(
        configs_scanned=1,
        servers_scanned=3,
        findings=(
            Finding(
                rule_id="MCP01-003",
                name="Hardcoded GitHub PAT",
                severity=Severity.CRITICAL,
                owasp="MCP01",
                file_path="/home/user/.claude.json",
                server_name="github",
                description="GitHub PAT hardcoded",
                remediation="Use env vars",
                evidence="env.TOKEN: ghp_***",
                cwe="CWE-798",
            ),
            Finding(
                rule_id="MCP07-002",
                name="Plaintext HTTP",
                severity=Severity.HIGH,
                owasp="MCP07",
                file_path="/home/user/.claude.json",
                server_name="api",
            ),
        ),
    )


class TestJsonOutput:
    def test_valid_json(self) -> None:
        result = _make_result()
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["version"] == "1.0"
        assert parsed["configs_scanned"] == 1
        assert parsed["passed"] is False

    def test_findings_included(self) -> None:
        result = _make_result()
        parsed = json.loads(format_json(result))
        assert len(parsed["findings"]) == 2
        assert parsed["findings"][0]["rule_id"] == "MCP01-003"
        assert parsed["findings"][0]["severity"] == "critical"

    def test_summary_counts(self) -> None:
        result = _make_result()
        parsed = json.loads(format_json(result))
        assert parsed["summary"]["critical"] == 1
        assert parsed["summary"]["high"] == 1
        assert parsed["summary"]["total"] == 2


class TestSarifOutput:
    def test_valid_sarif(self) -> None:
        result = _make_result()
        output = format_sarif(result)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

    def test_sarif_results(self) -> None:
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        results = parsed["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["ruleId"] == "MCP01-003"
        assert results[0]["level"] == "error"

    def test_sarif_rules(self) -> None:
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2
        rule_ids = {r["id"] for r in rules}
        assert "MCP01-003" in rule_ids
        assert "MCP07-002" in rule_ids

    def test_empty_result_valid_sarif(self) -> None:
        result = ScanResult()
        parsed = json.loads(format_sarif(result))
        assert parsed["version"] == "2.1.0"
        assert parsed["runs"][0]["results"] == []
