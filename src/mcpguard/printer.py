"""Rich terminal output -- all rendering logic lives here.

Every visual element is rendered through this module. Scanner logic
never imports Rich directly, enabling clean --json/--sarif output.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from .models import Finding, ScanResult, Severity

SEVERITY_STYLES: dict[Severity, tuple[str, str, str]] = {
    #                     (badge_style,        border,    icon)
    Severity.CRITICAL: ("bold white on red",   "red",     "CRITICAL"),
    Severity.HIGH:     ("bold white on red",   "red",     "HIGH    "),
    Severity.MEDIUM:   ("bold black on yellow","yellow",  "MEDIUM  "),
    Severity.LOW:      ("bold white on blue",  "blue",    "LOW     "),
    Severity.INFO:     ("bold white on cyan",  "dim",     "INFO    "),
}

LOGO = r"""
                                                  _
  _ __ ___   ___ _ __   __ _ _   _  __ _ _ __ __| |
 | '_ ` _ \ / __| '_ \ / _` | | | |/ _` | '__/ _` |
 | | | | | | (__| |_) | (_| | |_| | (_| | | | (_| |
 |_| |_| |_|\___| .__/ \__, |\__,_|\__,_|_|  \__,_|
                 |_|    |___/
"""


def print_header(console: Console, version: str) -> None:
    console.print(f"[bold blue]{LOGO}[/bold blue]", highlight=False)
    console.print(f"  [dim]v{version} -- MCP Security Scanner[/dim]\n")


def print_discovery(console: Console, configs: list[tuple[str, Any, Any]]) -> None:
    if not configs:
        console.print("[yellow]No MCP configuration files found.[/yellow]\n")
        console.print("[dim]Checked: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf[/dim]")
        return

    console.print(f"[bold]Found {len(configs)} MCP config(s):[/bold]")
    for client, path, _ in configs:
        console.print(f"  [green]+[/green] [bold]{client}[/bold]: [dim]{path}[/dim]")
    console.print()


def print_findings(console: Console, result: ScanResult) -> None:
    if not result.findings:
        console.print(
            Panel(
                "[bold green]No security issues found.[/bold green]\n\n"
                "[dim]All MCP server configurations passed security checks.[/dim]",
                title="[bold green]PASS[/bold green]",
                border_style="green",
                padding=(1, 2),
            )
        )
        return

    sorted_findings = sorted(result.findings, key=lambda f: f.severity, reverse=True)

    console.print(Rule("[bold]Findings[/bold]"))
    console.print()

    for i, finding in enumerate(sorted_findings, 1):
        _print_single_finding(console, finding, i)


def _print_single_finding(console: Console, finding: Finding, index: int) -> None:
    badge_style, border, icon = SEVERITY_STYLES[finding.severity]

    lines: list[str] = []

    # Severity badge + rule ID + OWASP
    header_parts = [f"[{badge_style}] {icon} [/{badge_style}]"]
    header_parts.append(f"  [bold]{finding.name}[/bold]")
    lines.append("".join(header_parts))

    # Metadata line
    meta_parts: list[str] = []
    if finding.owasp:
        meta_parts.append(f"[cyan]OWASP {finding.owasp}[/cyan]")
    meta_parts.append(f"[dim]Rule {finding.rule_id}[/dim]")
    if finding.cwe:
        meta_parts.append(f"[dim]{finding.cwe}[/dim]")
    lines.append("  ".join(meta_parts))

    # Server + file
    lines.append(f"[bold]Server:[/bold] {finding.server_name}  [dim]{finding.file_path}[/dim]")

    # Evidence
    if finding.evidence:
        lines.append(f"[bold]Evidence:[/bold] [yellow]{finding.evidence}[/yellow]")

    # Remediation
    if finding.remediation:
        lines.append(f"[bold]Fix:[/bold] [green]{finding.remediation}[/green]")

    panel = Panel(
        "\n".join(lines),
        border_style=border,
        padding=(0, 1),
    )
    console.print(panel)


def print_summary(console: Console, result: ScanResult) -> None:
    total = len(result.findings)
    status = "[bold green]PASS[/bold green]" if result.passed else "[bold red]FAIL[/bold red]"

    # Severity breakdown
    parts: list[str] = []
    if result.critical_count:
        parts.append(f"[bold red]{result.critical_count} critical[/bold red]")
    if result.high_count:
        parts.append(f"[red]{result.high_count} high[/red]")
    if result.medium_count:
        parts.append(f"[yellow]{result.medium_count} medium[/yellow]")
    if result.low_count:
        parts.append(f"[blue]{result.low_count} low[/blue]")

    findings_str = f"{total} ({', '.join(parts)})" if parts else "0"

    # Build summary lines
    summary = (
        f"  Status:           {status}\n"
        f"  Configs scanned:  {result.configs_scanned}\n"
        f"  Servers scanned:  {result.servers_scanned}\n"
        f"  Findings:         {findings_str}"
    )

    border = "red" if not result.passed else "green"
    console.print()
    console.print(Panel(
        summary, title="[bold]Scan Summary[/bold]",
        border_style=border, padding=(1, 1),
    ))


def print_owasp_coverage(console: Console, rules: list[dict]) -> None:
    owasp_ids = {
        r.get("info", {}).get("owasp", "")
        for r in rules if r.get("info", {}).get("owasp")
    }

    table = Table(
        title="[bold]OWASP MCP Top 10 Coverage[/bold]",
        show_header=True,
        header_style="bold",
        border_style="dim",
        padding=(0, 1),
        show_lines=False,
    )
    table.add_column("", width=3, justify="center")
    table.add_column("Risk", width=7)
    table.add_column("Description", ratio=1)

    owasp_risks = [
        ("MCP01", "Token Mismanagement & Secret Exposure"),
        ("MCP02", "Privilege Escalation via Scope Creep"),
        ("MCP03", "Tool Poisoning"),
        ("MCP04", "Supply Chain Attacks"),
        ("MCP05", "Command Injection & Execution"),
        ("MCP06", "Intent Flow Subversion"),
        ("MCP07", "Insufficient Authentication"),
        ("MCP08", "Lack of Audit & Telemetry"),
        ("MCP09", "Shadow MCP Servers"),
        ("MCP10", "Context Injection & Over-Sharing"),
    ]

    for risk_id, desc in owasp_risks:
        covered = risk_id in owasp_ids
        if covered:
            table.add_row("[green]Y[/green]", f"[bold]{risk_id}[/bold]", desc)
        else:
            table.add_row("[dim]-[/dim]", f"[dim]{risk_id}[/dim]", f"[dim]{desc}[/dim]")

    console.print()
    console.print(table)
    console.print()


def print_fix_result(
    console: Console,
    fixed_count: int,
    skipped_count: int,
    files_modified: list[str],
) -> None:
    if fixed_count == 0:
        console.print("[dim]Nothing to fix.[/dim]")
        return

    lines = [f"[bold green]{fixed_count}[/bold green] issues auto-fixed"]
    if skipped_count:
        lines.append(f"[dim]{skipped_count} skipped (manual fix required)[/dim]")
    lines.append("")
    lines.append("[bold]Modified files:[/bold]")
    for f in files_modified:
        lines.append(f"  [green]+[/green] {f}")
    lines.append("")
    lines.append("[dim]Review changes before committing.[/dim]")

    console.print(Panel(
        "\n".join(lines), title="[bold]Auto-Fix Results[/bold]",
        border_style="green",
    ))


# -- Structured output --------------------------------------------------------

def format_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "version": "1.0",
            "configs_scanned": result.configs_scanned,
            "servers_scanned": result.servers_scanned,
            "passed": result.passed,
            "summary": {
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "total": len(result.findings),
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "name": f.name,
                    "severity": f.severity.value,
                    "owasp": f.owasp,
                    "cwe": f.cwe,
                    "server_name": f.server_name,
                    "file_path": f.file_path,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
        },
        indent=2,
        default=str,
    )


def format_sarif(result: ScanResult) -> str:
    """Format findings as SARIF v2.1.0 for GitHub Security tab."""
    rules_map: dict[str, dict] = {}
    results_list: list[dict] = []

    sarif_severity = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    for finding in result.findings:
        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.name,
                "shortDescription": {"text": finding.name},
                "fullDescription": {"text": finding.description or finding.name},
                "helpUri": "https://owasp.org/www-project-mcp-top-10/",
                "properties": {"tags": ["security", "mcp", finding.owasp]},
            }

        results_list.append({
            "ruleId": finding.rule_id,
            "level": sarif_severity.get(finding.severity.value, "warning"),
            "message": {
                "text": f"{finding.name}: {finding.evidence}" if finding.evidence else finding.name,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path.replace("\\", "/")},
                    }
                }
            ],
            "properties": {
                "owasp": finding.owasp,
                "serverName": finding.server_name,
                "remediation": finding.remediation,
            },
        })

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpguard",
                        "informationUri": "https://github.com/loplop-h/mcpguard",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results_list,
            }
        ],
    }

    return json.dumps(sarif, indent=2, default=str)
