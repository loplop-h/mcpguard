"""Detection engine -- loads YAML rules and runs them against MCP configs."""

from __future__ import annotations

import importlib.resources
import math
import re
from pathlib import Path

import yaml

from .models import Finding, ServerConfig, Severity

# -- Rule loading -------------------------------------------------------------

_BUILTIN_RULES_PKG = "mcpguard.rules"


def load_rules(extra_dirs: tuple[str, ...] = ()) -> list[dict]:
    """Load all YAML rule files from built-in rules and extra directories."""
    rules: list[dict] = []

    # Built-in rules shipped with the package
    try:
        rules_dir = importlib.resources.files(_BUILTIN_RULES_PKG)
        for entry in rules_dir.iterdir():
            if entry.name.endswith((".yaml", ".yml")):
                text = entry.read_text(encoding="utf-8")
                parsed = yaml.safe_load(text)
                if isinstance(parsed, dict) and "id" in parsed:
                    rules.append(parsed)
                elif isinstance(parsed, list):
                    rules.extend(r for r in parsed if isinstance(r, dict) and "id" in r)
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        pass

    # Extra rule directories
    for dir_path in extra_dirs:
        p = Path(dir_path)
        if not p.is_dir():
            continue
        for f in sorted(p.glob("*.y*ml")):
            try:
                text = f.read_text(encoding="utf-8")
                parsed = yaml.safe_load(text)
                if isinstance(parsed, dict) and "id" in parsed:
                    rules.append(parsed)
                elif isinstance(parsed, list):
                    rules.extend(r for r in parsed if isinstance(r, dict) and "id" in r)
            except (OSError, yaml.YAMLError):
                continue

    return rules


# -- Scanning -----------------------------------------------------------------

def scan_server(server: ServerConfig, rules: list[dict]) -> list[Finding]:
    """Run all rules against a single server config. Returns findings."""
    findings: list[Finding] = []

    for rule in rules:
        rule_findings = _run_rule(server, rule)
        findings.extend(rule_findings)

    return findings


def _run_rule(server: ServerConfig, rule: dict) -> list[Finding]:
    """Run a single rule against a server config."""
    rule.get("info", {})
    detection = rule.get("detection", {})
    target = detection.get("target", "config")

    if target != "config":
        return []

    scope = detection.get("scope", "all")
    match_config = detection.get("match", {})
    match_type = match_config.get("type", "regex")

    values_to_check = _get_scope_values(server, scope)

    if match_type == "regex":
        return _match_regex(server, rule, values_to_check)
    if match_type == "check":
        return _match_check(server, rule)
    if match_type == "entropy":
        return _match_entropy(server, rule, values_to_check)

    return []


def _get_scope_values(server: ServerConfig, scope: str) -> list[tuple[str, str]]:
    """Extract (label, value) pairs from the server config based on scope."""
    pairs: list[tuple[str, str]] = []

    if scope in ("env_values", "all"):
        for k, v in server.env.items():
            pairs.append((f"env.{k}", v))

    if scope in ("args", "all"):
        for i, arg in enumerate(server.args):
            pairs.append((f"args[{i}]", arg))

    if scope in ("headers", "all"):
        for k, v in server.headers.items():
            pairs.append((f"headers.{k}", v))

    if scope in ("url", "all") and server.url:
        pairs.append(("url", server.url))

    if scope in ("command", "all") and server.command:
        pairs.append(("command", server.command))

    if scope in ("always_allow", "all"):
        for tool in server.always_allow:
            pairs.append(("alwaysAllow", tool))

    return pairs


def _match_regex(
    server: ServerConfig,
    rule: dict,
    values: list[tuple[str, str]],
) -> list[Finding]:
    """Match regex patterns against values."""
    info = rule.get("info", {})
    detection = rule.get("detection", {})
    match_config = detection.get("match", {})
    patterns = match_config.get("patterns", [])
    findings: list[Finding] = []

    for label, value in values:
        for pattern in patterns:
            try:
                if re.search(pattern, value, re.IGNORECASE):
                    masked = _mask_secret(value)
                    findings.append(Finding(
                        rule_id=rule["id"],
                        name=info.get("name", rule["id"]),
                        severity=Severity(info.get("severity", "medium")),
                        owasp=info.get("owasp", ""),
                        file_path=server.source_file,
                        server_name=server.name,
                        description=info.get("description", ""),
                        remediation=info.get("remediation", ""),
                        evidence=f"{label}: {masked}",
                        cwe=info.get("cwe", ""),
                    ))
                    break  # one finding per value per rule
            except re.error:
                continue

    return findings


def _match_check(server: ServerConfig, rule: dict) -> list[Finding]:
    """Run a named check function against the server config."""
    info = rule.get("info", {})
    detection = rule.get("detection", {})
    check_name = detection.get("match", {}).get("check", "")

    checks: dict[str, callable] = {
        "http_no_auth": _check_http_no_auth,
        "http_not_https": _check_http_not_https,
        "always_allow_wildcard": _check_always_allow_wildcard,
        "unpinned_version": _check_unpinned_version,
        "localhost_url": _check_localhost_url,
        "dangerous_command": _check_dangerous_command,
    }

    check_fn = checks.get(check_name)
    if check_fn is None:
        return []

    evidence = check_fn(server)
    if evidence is None:
        return []

    return [Finding(
        rule_id=rule["id"],
        name=info.get("name", rule["id"]),
        severity=Severity(info.get("severity", "medium")),
        owasp=info.get("owasp", ""),
        file_path=server.source_file,
        server_name=server.name,
        description=info.get("description", ""),
        remediation=info.get("remediation", ""),
        evidence=evidence,
        cwe=info.get("cwe", ""),
    )]


def _match_entropy(
    server: ServerConfig,
    rule: dict,
    values: list[tuple[str, str]],
) -> list[Finding]:
    """Detect high-entropy strings (potential secrets)."""
    info = rule.get("info", {})
    detection = rule.get("detection", {})
    threshold = detection.get("match", {}).get("threshold", 4.5)
    min_length = detection.get("match", {}).get("min_length", 16)
    findings: list[Finding] = []

    for label, value in values:
        if len(value) < min_length:
            continue
        # Skip values that look like env var references
        if value.startswith("${") or value.startswith("$"):
            continue
        entropy = _shannon_entropy(value)
        if entropy >= threshold:
            findings.append(Finding(
                rule_id=rule["id"],
                name=info.get("name", rule["id"]),
                severity=Severity(info.get("severity", "medium")),
                owasp=info.get("owasp", ""),
                file_path=server.source_file,
                server_name=server.name,
                description=info.get("description", ""),
                remediation=info.get("remediation", ""),
                evidence=f"{label}: entropy={entropy:.1f} (threshold={threshold})",
                cwe=info.get("cwe", ""),
            ))

    return findings


# -- Check functions ----------------------------------------------------------

def _check_http_no_auth(server: ServerConfig) -> str | None:
    if (
        server.transport in ("http", "sse")
        and server.url
        and not server.headers.get("Authorization")
        and not server.headers.get("authorization")
    ):
        return f"url: {server.url} (no Authorization header)"
    return None


def _check_http_not_https(server: ServerConfig) -> str | None:
    if server.url and server.url.startswith("http://"):
        return f"url: {server.url}"
    return None


def _check_always_allow_wildcard(server: ServerConfig) -> str | None:
    for tool in server.always_allow:
        if tool == "*":
            return "alwaysAllow: ['*'] (all tools auto-approved)"
    return None


def _check_unpinned_version(server: ServerConfig) -> str | None:
    for arg in server.args:
        if "@latest" in arg:
            return f"args: {arg} (unpinned @latest version)"
        if arg.startswith("-y") or arg == "--yes":
            continue
        if (
            "@" in arg
            and not re.search(r"@\d+\.", arg)
            and not arg.startswith("-")
            and re.match(r"^@?[\w\-/]+$", arg)
        ):
                return f"args: {arg} (no version pinned)"
    return None


def _check_localhost_url(server: ServerConfig) -> str | None:
    if not server.url:
        return None
    url_lower = server.url.lower()
    local_patterns = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]")
    for pat in local_patterns:
        if pat in url_lower:
            return f"url: {server.url} (localhost/dev server)"
    return None


def _check_dangerous_command(server: ServerConfig) -> str | None:
    dangerous = {"rm", "sudo", "chmod", "chown", "mkfs", "dd", "curl|sh", "wget|sh"}
    full_cmd = f"{server.command} {' '.join(server.args)}".lower()
    for d in dangerous:
        if d in full_cmd:
            return f"command: {server.command} {' '.join(server.args[:3])}"
    return None


# -- Utilities ----------------------------------------------------------------

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]
