"""Data models for scan results, findings, and server configurations."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


class Finding(BaseModel):
    """A single security finding from a scan."""

    rule_id: str
    name: str
    severity: Severity
    owasp: str = ""
    file_path: str = ""
    server_name: str = ""
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    cwe: str = ""

    model_config = {"frozen": True}


class ServerConfig(BaseModel):
    """Parsed MCP server entry from a config file."""

    name: str
    source_file: str
    client: str = ""
    command: str = ""
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    transport: str = "stdio"
    always_allow: tuple[str, ...] = ()
    raw: dict = Field(default_factory=dict)

    model_config = {"frozen": True}


class ScanResult(BaseModel):
    """Aggregated result of a full scan."""

    configs_scanned: int = 0
    servers_scanned: int = 0
    findings: tuple[Finding, ...] = ()
    configs: tuple[str, ...] = ()

    model_config = {"frozen": True}

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0
