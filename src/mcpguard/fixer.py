"""Auto-fix engine -- remediates security findings in MCP configs.

Supports automatic fixes for:
- MCP01: Replace hardcoded secrets with environment variable references
- MCP07: Upgrade http:// URLs to https://
- MCP02: Remove wildcard alwaysAllow
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .models import Finding

# -- Fixable rules ------------------------------------------------------------

FIXABLE_RULES = frozenset({
    "MCP01-001", "MCP01-002", "MCP01-003", "MCP01-004",
    "MCP01-005", "MCP01-006", "MCP01-008",
    "MCP07-002",
    "MCP02-001",
})

# Map env key names to standard variable names
SECRET_VAR_NAMES: dict[str, str] = {
    "GITHUB_TOKEN": "GITHUB_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN": "GITHUB_PERSONAL_ACCESS_TOKEN",
    "OPENAI_API_KEY": "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY",
    "API_KEY": "API_KEY",
    "SECRET_KEY": "SECRET_KEY",
    "DATABASE_URL": "DATABASE_URL",
}


def can_fix(finding: Finding) -> bool:
    return finding.rule_id in FIXABLE_RULES


def fix_findings(
    findings: list[Finding],
    dry_run: bool = False,
) -> tuple[int, int, list[str]]:
    """Apply auto-fixes for supported findings.

    Returns (fixed_count, skipped_count, modified_files).
    """
    # Group findings by file
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if can_fix(f):
            by_file.setdefault(f.file_path, []).append(f)

    fixed = 0
    skipped = 0
    modified: list[str] = []

    for file_path, file_findings in by_file.items():
        path = Path(file_path)
        if not path.is_file():
            skipped += len(file_findings)
            continue

        try:
            original = path.read_text(encoding="utf-8")
            config = json.loads(original)
        except (OSError, json.JSONDecodeError):
            skipped += len(file_findings)
            continue

        changed = False
        servers = config.get("mcpServers") or config.get("servers") or {}

        for finding in file_findings:
            server = servers.get(finding.server_name)
            if server is None:
                skipped += 1
                continue

            result = _apply_fix(finding, server)
            if result:
                changed = True
                fixed += 1
            else:
                skipped += 1

        if changed and not dry_run:
            # Backup original
            backup = Path(f"{file_path}.mcpguard-backup")
            if not backup.exists():
                shutil.copy2(file_path, backup)

            # Write fixed config
            output = json.dumps(config, indent=2, ensure_ascii=False)
            path.write_text(output + "\n", encoding="utf-8")
            modified.append(file_path)
        elif changed:
            modified.append(f"{file_path} (dry-run)")

    return fixed, skipped, modified


def _apply_fix(finding: Finding, server: dict) -> bool:
    """Apply a single fix. Returns True if the server dict was modified."""
    rule = finding.rule_id

    # MCP01: Replace hardcoded secrets with env var references
    if rule.startswith("MCP01-") and rule != "MCP01-007":
        return _fix_hardcoded_secret(finding, server)

    # MCP07-002: Upgrade http:// to https://
    if rule == "MCP07-002":
        return _fix_http_to_https(server)

    # MCP02-001: Remove wildcard alwaysAllow
    if rule == "MCP02-001":
        return _fix_wildcard_allow(server)

    return False


def _fix_hardcoded_secret(finding: Finding, server: dict) -> bool:
    """Replace hardcoded secret values with ${VAR_NAME} references."""
    # Fix secrets in env block
    env = server.get("env")
    if isinstance(env, dict):
        for key, value in list(env.items()):
            if (
                isinstance(value, str)
                and not value.startswith("${")
                and _looks_like_secret(value)
            ):
                    var_name = SECRET_VAR_NAMES.get(key, key)
                    env[key] = f"${{{var_name}}}"
                    return True

    # Fix secrets in headers
    headers = server.get("headers")
    if isinstance(headers, dict):
        auth = headers.get("Authorization", headers.get("authorization", ""))
        if isinstance(auth, str) and "Bearer " in auth:
            token = auth.split("Bearer ", 1)[1].strip()
            if len(token) > 20 and not token.startswith("${"):
                headers["Authorization"] = "Bearer ${API_TOKEN}"
                return True

    return False


def _fix_http_to_https(server: dict) -> bool:
    """Upgrade http:// URLs to https://."""
    url = server.get("url", "")
    if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
        server["url"] = "https://" + url[7:]
        return True
    return False


def _fix_wildcard_allow(server: dict) -> bool:
    """Remove wildcard from alwaysAllow."""
    allow = server.get("alwaysAllow", [])
    if "*" in allow:
        server["alwaysAllow"] = [t for t in allow if t != "*"]
        if not server["alwaysAllow"]:
            del server["alwaysAllow"]
        return True
    return False


def _looks_like_secret(value: str) -> bool:
    """Heuristic: does this value look like a hardcoded secret?"""
    if len(value) < 16:
        return False
    if value.startswith("${") or value.startswith("$"):
        return False

    secret_prefixes = (
        "sk-", "sk_", "ghp_", "gho_", "ghs_", "github_pat_",
        "sk-ant-", "rk_live_", "sk_live_", "xox", "eyJ",
        "AKIA", "Bearer ",
    )
    for prefix in secret_prefixes:
        if value.startswith(prefix):
            return True

    # High entropy check (simple)
    return bool(len(set(value)) > len(value) * 0.5 and len(value) >= 20)
