"""Auto-discover MCP configuration files across all supported clients."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .models import ServerConfig

# -- Config file locations per client per OS ----------------------------------

def _home() -> Path:
    return Path.home()


def _appdata() -> Path:
    return Path(os.environ.get("APPDATA", _home() / "AppData" / "Roaming"))


def _claude_desktop_paths() -> list[Path]:
    if sys.platform == "win32":
        return [_appdata() / "Claude" / "claude_desktop_config.json"]
    if sys.platform == "darwin":
        base = _home() / "Library" / "Application Support" / "Claude"
        return [base / "claude_desktop_config.json"]
    return [_home() / ".config" / "claude-desktop" / "claude_desktop_config.json"]


def _claude_code_paths() -> list[Path]:
    return [
        _home() / ".claude.json",
        Path(".mcp.json"),
        Path(".claude") / "mcp.json",
    ]


def _cursor_paths() -> list[Path]:
    return [
        _home() / ".cursor" / "mcp.json",
        Path(".cursor") / "mcp.json",
    ]


def _vscode_paths() -> list[Path]:
    user_dir: Path
    if sys.platform == "win32":
        user_dir = _appdata() / "Code" / "User"
    elif sys.platform == "darwin":
        user_dir = _home() / "Library" / "Application Support" / "Code" / "User"
    else:
        user_dir = _home() / ".config" / "Code" / "User"
    return [
        user_dir / "mcp.json",
        Path(".vscode") / "mcp.json",
    ]


def _windsurf_paths() -> list[Path]:
    return [_home() / ".codeium" / "windsurf" / "mcp_config.json"]


CLIENT_PATHS: dict[str, callable] = {
    "claude-desktop": _claude_desktop_paths,
    "claude-code": _claude_code_paths,
    "cursor": _cursor_paths,
    "vscode": _vscode_paths,
    "windsurf": _windsurf_paths,
}


# -- Discovery ----------------------------------------------------------------

def discover_configs(extra_paths: tuple[str, ...] = ()) -> list[tuple[str, Path, dict]]:
    """Find all MCP config files on the system.

    Returns list of (client_name, file_path, parsed_json) tuples.
    """
    found: list[tuple[str, Path, dict]] = []

    for client, path_fn in CLIENT_PATHS.items():
        for path in path_fn():
            resolved = path.expanduser().resolve()
            config = _try_read_config(resolved)
            if config is not None:
                found.append((client, resolved, config))

    for extra in extra_paths:
        p = Path(extra).expanduser().resolve()
        config = _try_read_config(p)
        if config is not None:
            found.append(("custom", p, config))

    return found


def extract_servers(
    client: str,
    file_path: Path,
    config: dict,
) -> list[ServerConfig]:
    """Extract server definitions from a parsed config."""
    # VS Code uses "servers", everyone else uses "mcpServers"
    servers_dict = config.get("mcpServers") or config.get("servers") or {}
    result: list[ServerConfig] = []

    for name, raw in servers_dict.items():
        if not isinstance(raw, dict):
            continue

        transport = raw.get("type", "stdio")
        if "url" in raw and transport == "stdio":
            transport = "http"

        result.append(ServerConfig(
            name=name,
            source_file=str(file_path),
            client=client,
            command=raw.get("command", ""),
            args=tuple(raw.get("args", [])),
            env=dict(raw.get("env", {})),
            url=raw.get("url", ""),
            headers=dict(raw.get("headers", {})),
            transport=transport,
            always_allow=tuple(raw.get("alwaysAllow", [])),
            raw=raw,
        ))

    return result


def _try_read_config(path: Path) -> dict[str, Any] | None:
    """Try to read and parse a JSON config file. Returns None on failure."""
    try:
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
        if not isinstance(data, dict):
            return None
        # Must have either mcpServers or servers key
        if "mcpServers" in data or "servers" in data:
            return data
        return None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
