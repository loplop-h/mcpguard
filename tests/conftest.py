"""Shared test fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def tmp_config(tmp_path: Path):
    """Create a temporary MCP config file and return its path."""
    def _create(data: dict, filename: str = "mcp.json") -> Path:
        p = tmp_path / filename
        p.write_text(json.dumps(data), encoding="utf-8")
        return p
    return _create


@pytest.fixture()
def vulnerable_config() -> dict:
    """A config with multiple known vulnerabilities for testing."""
    return {
        "mcpServers": {
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github@latest"],
                "env": {
                    "GITHUB_TOKEN": "ghp_abc123def456ghi789jkl012mno345pqr678"
                },
            },
            "unsafe-remote": {
                "type": "http",
                "url": "http://api.example.com/mcp",
            },
            "dev-server": {
                "type": "http",
                "url": "http://localhost:3001/mcp",
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
                },
            },
            "auto-approve-all": {
                "command": "node",
                "args": ["server.js"],
                "alwaysAllow": ["*"],
            },
        }
    }


@pytest.fixture()
def safe_config() -> dict:
    """A config with no vulnerabilities."""
    return {
        "mcpServers": {
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github@1.2.3"],
                "env": {
                    "GITHUB_TOKEN": "${GITHUB_TOKEN}"
                },
            },
            "api": {
                "type": "http",
                "url": "https://api.example.com/mcp",
                "headers": {
                    "Authorization": "Bearer ${API_TOKEN}"
                },
            },
        }
    }
