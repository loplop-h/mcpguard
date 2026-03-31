"""Tests for MCP config discovery."""

from __future__ import annotations

import json
from pathlib import Path

from mcpguard.discovery import discover_configs, extract_servers


class TestExtractServers:
    def test_extracts_stdio_server(self) -> None:
        config = {
            "mcpServers": {
                "test": {
                    "command": "npx",
                    "args": ["-y", "some-package"],
                    "env": {"KEY": "value"},
                }
            }
        }
        servers = extract_servers("test-client", Path("/fake/path.json"), config)
        assert len(servers) == 1
        assert servers[0].name == "test"
        assert servers[0].command == "npx"
        assert servers[0].args == ("-y", "some-package")
        assert servers[0].env == {"KEY": "value"}
        assert servers[0].transport == "stdio"

    def test_extracts_http_server(self) -> None:
        config = {
            "mcpServers": {
                "remote": {
                    "type": "http",
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer token123"},
                }
            }
        }
        servers = extract_servers("cursor", Path("/fake.json"), config)
        assert len(servers) == 1
        assert servers[0].transport == "http"
        assert servers[0].url == "https://api.example.com/mcp"
        assert servers[0].headers["Authorization"] == "Bearer token123"

    def test_handles_vscode_servers_key(self) -> None:
        config = {
            "servers": {
                "memory": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-memory"],
                }
            }
        }
        servers = extract_servers("vscode", Path("/fake.json"), config)
        assert len(servers) == 1
        assert servers[0].name == "memory"

    def test_handles_empty_config(self) -> None:
        servers = extract_servers("test", Path("/fake.json"), {})
        assert servers == []

    def test_handles_always_allow(self) -> None:
        config = {
            "mcpServers": {
                "test": {
                    "command": "node",
                    "args": ["server.js"],
                    "alwaysAllow": ["Read", "Grep"],
                }
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        assert servers[0].always_allow == ("Read", "Grep")

    def test_multiple_servers(self) -> None:
        config = {
            "mcpServers": {
                "a": {"command": "cmd1", "args": []},
                "b": {"command": "cmd2", "args": []},
                "c": {"command": "cmd3", "args": []},
            }
        }
        servers = extract_servers("test", Path("/f.json"), config)
        assert len(servers) == 3
        names = {s.name for s in servers}
        assert names == {"a", "b", "c"}


class TestDiscoverConfigs:
    def test_discovers_extra_paths(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"test": {"command": "echo"}}}
        p = tmp_path / "custom.json"
        p.write_text(json.dumps(config), encoding="utf-8")

        found = discover_configs(extra_paths=(str(p),))
        paths = [str(path) for _, path, _ in found]
        assert str(p) in paths

    def test_skips_invalid_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json{{{", encoding="utf-8")

        found = discover_configs(extra_paths=(str(p),))
        custom = [f for f in found if f[0] == "custom"]
        assert len(custom) == 0

    def test_skips_missing_mcp_key(self, tmp_path: Path) -> None:
        p = tmp_path / "no_mcp.json"
        p.write_text(json.dumps({"something": "else"}), encoding="utf-8")

        found = discover_configs(extra_paths=(str(p),))
        custom = [f for f in found if f[0] == "custom"]
        assert len(custom) == 0
