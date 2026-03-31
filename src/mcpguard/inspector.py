"""MCP Server Inspector -- connects to servers, lists tools, detects poisoning.

Spawns MCP servers via stdio, performs the JSON-RPC handshake, and inspects
tool definitions for injection patterns, shadowing, and suspicious behavior.
Does NOT execute any tools -- only reads metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, ServerConfig, Severity

# -- Injection patterns in tool descriptions ----------------------------------

INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(previous|all|prior|above)\s+(instructions|prompts|rules)", "Instruction override"),
    (r"(disregard|forget)\s+(all|your|prior|previous)", "Memory wipe attempt"),
    (r"act\s+as\s+(a|an|if)", "Role injection"),
    (r"you\s+are\s+now", "Identity override"),
    (r"system\s*prompt", "System prompt reference"),
    (r"new\s+(role|instructions|persona)", "Role reassignment"),
    (r"override\s+(instructions|safety|rules)", "Safety override"),
    (r"do\s+not\s+(tell|reveal|mention|inform)\s+(the\s+)?user", "User deception"),
    (r"(read|access|cat|open)\s+[~/\.].*"
     r"(ssh|env|secret|key|password|credential|token)", "File exfiltration"),
    (r"(send|post|transmit|exfiltrate|upload)\s+.*"
     r"(data|content|file|secret|key|token)", "Data exfiltration"),
    (r"(curl|wget|fetch|http)\s+https?://", "Network callback"),
    (r"<\s*important\s*>|<\s*system\s*>|<\s*instruction\s*>", "XML tag injection"),
    (r"IMPORTANT\s*:", "Priority injection"),
    (r"begin\s+(system|hidden|secret)\s+instructions?", "Hidden instruction block"),
]

# Maximum safe description length (chars)
MAX_DESCRIPTION_LENGTH = 1000

# Suspicious tool name patterns
SUSPICIOUS_TOOL_NAMES = {
    "execute", "exec", "eval", "run_command", "shell",
    "system", "admin", "sudo", "root", "delete_all",
}


@dataclass(frozen=True)
class ToolInfo:
    """Metadata about a single tool from an MCP server."""

    name: str
    description: str
    input_schema: dict = field(default_factory=dict)
    server_name: str = ""
    source_file: str = ""

    @property
    def description_hash(self) -> str:
        content = f"{self.name}:{self.description}:{json.dumps(self.input_schema, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class InspectionResult:
    """Result of inspecting a single MCP server."""

    server_name: str
    source_file: str
    tools: tuple[ToolInfo, ...] = ()
    findings: tuple[Finding, ...] = ()
    error: str = ""
    connected: bool = False


# -- Server connection --------------------------------------------------------

def inspect_server(
    server: ServerConfig,
    timeout: float = 15.0,
) -> InspectionResult:
    """Connect to an MCP server, list tools, and scan for issues.

    Only works with stdio transport. Returns findings without executing tools.
    """
    if server.transport != "stdio" or not server.command:
        return InspectionResult(
            server_name=server.name,
            source_file=server.source_file,
            error="Only stdio servers can be inspected",
        )

    try:
        tools, error = _connect_and_list_tools(server, timeout)
    except Exception as exc:
        return InspectionResult(
            server_name=server.name,
            source_file=server.source_file,
            error=str(exc),
        )

    if error:
        return InspectionResult(
            server_name=server.name,
            source_file=server.source_file,
            error=error,
        )

    # Analyze tools for security issues
    findings = _analyze_tools(tools, server)

    return InspectionResult(
        server_name=server.name,
        source_file=server.source_file,
        tools=tuple(tools),
        findings=tuple(findings),
        connected=True,
    )


def _connect_and_list_tools(
    server: ServerConfig,
    timeout: float,
) -> tuple[list[ToolInfo], str]:
    """Spawn server process, handshake, list tools, then kill it."""
    cmd = [server.command, *server.args]

    # Build environment
    env = dict(os.environ)
    for k, v in server.env.items():
        # Skip env var references -- they're not resolved here
        if not v.startswith("${"):
            env[k] = v

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=None,
        )
    except FileNotFoundError:
        return [], f"Command not found: {server.command}"
    except OSError as exc:
        return [], f"Failed to start: {exc}"

    try:
        # MCP JSON-RPC initialize
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpguard", "version": "0.1.0"},
            },
        }
        _send_message(proc, init_request)
        init_response = _read_message(proc, timeout=timeout)

        if not init_response or "result" not in init_response:
            return [], "Server did not respond to initialize"

        # Send initialized notification
        _send_message(proc, {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })

        # Small delay to let server process notification
        time.sleep(0.1)

        # List tools
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        _send_message(proc, tools_request)
        tools_response = _read_message(proc, timeout=timeout)

        if not tools_response or "result" not in tools_response:
            return [], "Server did not respond to tools/list"

        raw_tools = tools_response["result"].get("tools", [])
        tools = [
            ToolInfo(
                name=t.get("name", ""),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
                server_name=server.name,
                source_file=server.source_file,
            )
            for t in raw_tools
            if isinstance(t, dict)
        ]

        return tools, ""

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def _send_message(proc: subprocess.Popen, message: dict) -> None:
    """Send a JSON-RPC message via stdin (newline-delimited)."""
    data = json.dumps(message) + "\n"
    proc.stdin.write(data.encode())
    proc.stdin.flush()


def _read_message(proc: subprocess.Popen, timeout: float = 10.0) -> dict | None:
    """Read a JSON-RPC message from stdout with timeout.

    Supports both newline-delimited JSON (MCP stdio) and Content-Length
    framed messages (LSP-style). Uses a background thread for cross-platform
    compatibility (selectors doesn't work with pipes on Windows).
    """
    import queue
    import threading

    result_queue: queue.Queue[bytes | None] = queue.Queue()

    def _reader() -> None:
        try:
            buf = b""
            while True:
                byte = proc.stdout.read(1)
                if not byte:
                    result_queue.put(None)
                    return
                buf += byte

                # Try Content-Length framing (LSP-style)
                if b"\r\n\r\n" in buf:
                    header_end = buf.index(b"\r\n\r\n")
                    header_str = buf[:header_end].decode(errors="ignore")
                    cl = -1
                    for line in header_str.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            cl = int(line.split(":", 1)[1].strip())
                    if cl >= 0:
                        body_start = header_end + 4
                        remaining = cl - (len(buf) - body_start)
                        if remaining > 0:
                            extra = proc.stdout.read(remaining)
                            if extra:
                                buf += extra
                        result_queue.put(buf[body_start:body_start + cl])
                        return

                # Try newline-delimited JSON (MCP stdio)
                if buf.endswith(b"\n"):
                    line = buf.strip()
                    if line and line.startswith(b"{"):
                        result_queue.put(line)
                        return
                    buf = b""  # not JSON, reset
        except (OSError, ValueError):
            result_queue.put(None)

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()

    try:
        data = result_queue.get(timeout=timeout)
    except queue.Empty:
        return None

    if data is None:
        return None

    try:
        return json.loads(data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# -- Tool analysis ------------------------------------------------------------

def _analyze_tools(tools: list[ToolInfo], server: ServerConfig) -> list[Finding]:
    """Analyze tool definitions for security issues."""
    findings: list[Finding] = []

    for tool in tools:
        findings.extend(_check_tool_poisoning(tool))
        findings.extend(_check_suspicious_name(tool))
        findings.extend(_check_long_description(tool))
        findings.extend(_check_missing_schema(tool))

    # Cross-tool checks
    findings.extend(_check_tool_shadowing(tools, server))

    return findings


def _check_tool_poisoning(tool: ToolInfo) -> list[Finding]:
    """Check tool description for injection patterns."""
    findings: list[Finding] = []
    desc_lower = tool.description.lower()

    for pattern, label in INJECTION_PATTERNS:
        if re.search(pattern, desc_lower):
            findings.append(Finding(
                rule_id="MCP03-001",
                name=f"Tool Poisoning: {label}",
                severity=Severity.CRITICAL,
                owasp="MCP03",
                file_path=tool.source_file,
                server_name=tool.server_name,
                description=(
                    f"Tool '{tool.name}' description contains an injection "
                    f"pattern ({label}). This could manipulate agent behavior."
                ),
                remediation="Review the tool description and remove injected instructions",
                evidence=f"tool: {tool.name}, pattern: {label}",
                cwe="CWE-94",
            ))

    return findings


def _check_suspicious_name(tool: ToolInfo) -> list[Finding]:
    """Flag tools with suspicious names."""
    name_lower = tool.name.lower()
    for suspicious in SUSPICIOUS_TOOL_NAMES:
        if suspicious in name_lower:
            return [Finding(
                rule_id="MCP03-002",
                name="Suspicious Tool Name",
                severity=Severity.HIGH,
                owasp="MCP03",
                file_path=tool.source_file,
                server_name=tool.server_name,
                description=f"Tool '{tool.name}' has a name suggesting dangerous capabilities",
                remediation="Verify this tool is legitimate and necessary",
                evidence=f"tool: {tool.name}, matched: {suspicious}",
                cwe="CWE-269",
            )]
    return []


def _check_long_description(tool: ToolInfo) -> list[Finding]:
    """Flag unusually long tool descriptions (may hide injections)."""
    if len(tool.description) > MAX_DESCRIPTION_LENGTH:
        return [Finding(
            rule_id="MCP03-003",
            name="Unusually Long Tool Description",
            severity=Severity.MEDIUM,
            owasp="MCP03",
            file_path=tool.source_file,
            server_name=tool.server_name,
            description=(
                f"Tool '{tool.name}' has a {len(tool.description)}-char description "
                f"(max recommended: {MAX_DESCRIPTION_LENGTH}). Long descriptions "
                "may hide injected instructions."
            ),
            remediation="Review the full tool description for hidden instructions",
            evidence=f"tool: {tool.name}, length: {len(tool.description)} chars",
            cwe="CWE-94",
        )]
    return []


def _check_missing_schema(tool: ToolInfo) -> list[Finding]:
    """Flag tools without input schema validation."""
    if not tool.input_schema or tool.input_schema == {}:
        return [Finding(
            rule_id="MCP05-003",
            name="Tool Missing Input Schema",
            severity=Severity.MEDIUM,
            owasp="MCP05",
            file_path=tool.source_file,
            server_name=tool.server_name,
            description=(
                f"Tool '{tool.name}' has no input schema. Without schema "
                "validation, the tool may accept arbitrary input."
            ),
            remediation="Add an inputSchema to validate tool arguments",
            evidence=f"tool: {tool.name}",
            cwe="CWE-20",
        )]
    return []


def _check_tool_shadowing(
    tools: list[ToolInfo],
    server: ServerConfig,
) -> list[Finding]:
    """Detect duplicate tool names (shadowing attack)."""
    seen: dict[str, str] = {}
    findings: list[Finding] = []

    for tool in tools:
        if tool.name in seen:
            findings.append(Finding(
                rule_id="MCP03-004",
                name="Tool Name Shadowing",
                severity=Severity.HIGH,
                owasp="MCP03",
                file_path=tool.source_file,
                server_name=tool.server_name,
                description=(
                    f"Tool '{tool.name}' appears multiple times. "
                    "A malicious server could shadow legitimate tools."
                ),
                remediation="Remove duplicate tool definitions",
                evidence=f"tool: {tool.name}, duplicate",
                cwe="CWE-694",
            ))
        seen[tool.name] = tool.server_name

    return findings


# -- Rug pull detection -------------------------------------------------------

HASH_FILE = Path.home() / ".mcpguard" / "tool_hashes.json"


def load_previous_hashes() -> dict[str, dict[str, str]]:
    """Load previously saved tool hashes."""
    try:
        if HASH_FILE.is_file():
            return json.loads(HASH_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_hashes(hashes: dict[str, dict[str, str]]) -> None:
    """Save current tool hashes for future comparison."""
    HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
    HASH_FILE.write_text(
        json.dumps(hashes, indent=2),
        encoding="utf-8",
    )


def detect_rug_pulls(
    server_name: str,
    tools: tuple[ToolInfo, ...],
    previous: dict[str, dict[str, str]],
) -> list[Finding]:
    """Compare current tool hashes against previous scan."""
    findings: list[Finding] = []
    prev_server = previous.get(server_name, {})

    if not prev_server:
        return []  # First scan, nothing to compare

    for tool in tools:
        prev_hash = prev_server.get(tool.name)
        if prev_hash and prev_hash != tool.description_hash:
            findings.append(Finding(
                rule_id="MCP03-005",
                name="Tool Definition Changed (Rug Pull)",
                severity=Severity.CRITICAL,
                owasp="MCP03",
                file_path=tool.source_file,
                server_name=server_name,
                description=(
                    f"Tool '{tool.name}' definition has changed since last scan. "
                    "This could indicate a rug pull attack where a server silently "
                    "modifies tool behavior after initial approval."
                ),
                remediation="Review the tool definition changes and re-approve if legitimate",
                evidence=f"tool: {tool.name}, prev: {prev_hash}, now: {tool.description_hash}",
                cwe="CWE-494",
            ))

    # Check for new tools added since last scan
    current_names = {t.name for t in tools}
    for prev_name in prev_server:
        if prev_name not in current_names:
            findings.append(Finding(
                rule_id="MCP03-006",
                name="Tool Removed Since Last Scan",
                severity=Severity.MEDIUM,
                owasp="MCP03",
                file_path=tools[0].source_file if tools else "",
                server_name=server_name,
                description=f"Tool '{prev_name}' was present in previous scan but is now missing",
                remediation="Verify the tool removal was intentional",
                evidence=f"tool: {prev_name}, status: removed",
                cwe="CWE-494",
            ))

    return findings
