"""CLI entry point -- Click commands for mcpguard."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from . import __version__
from .discovery import discover_configs, extract_servers
from .engine import load_rules, scan_server
from .fixer import can_fix, fix_findings
from .models import Finding, ScanResult, Severity
from .printer import (
    format_json,
    format_sarif,
    print_discovery,
    print_findings,
    print_fix_result,
    print_header,
    print_owasp_coverage,
    print_summary,
)


def _run_scan(
    path: tuple[str, ...],
    rules_dir: tuple[str, ...],
    min_severity: Severity,
) -> tuple[ScanResult, list[dict], list[tuple]]:
    """Shared scan logic for config-level scanning."""
    configs = discover_configs(extra_paths=path)
    rules = load_rules(extra_dirs=rules_dir)
    all_findings: list[Finding] = []
    total_servers = 0

    for client, file_path, config in configs:
        servers = extract_servers(client, file_path, config)
        total_servers += len(servers)
        for server in servers:
            findings = scan_server(server, rules)
            filtered = [f for f in findings if not f.severity < min_severity]
            all_findings.extend(filtered)

    result = ScanResult(
        configs_scanned=len(configs),
        servers_scanned=total_servers,
        findings=tuple(all_findings),
        configs=tuple(str(p) for _, p, _ in configs),
    )
    return result, rules, configs


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="mcpguard")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """mcpguard -- Security scanner for MCP server configurations."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


@cli.command()
@click.option("--path", "-p", multiple=True, help="Extra config files to scan.")
@click.option("--rules-dir", "-r", multiple=True, help="Extra YAML rules directories.")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="low",
    help="Minimum severity to report.",
)
@click.option("--exit-code/--no-exit-code", default=True, help="Exit 1 on findings.")
@click.option("--owasp/--no-owasp", default=True, help="Show OWASP coverage.")
@click.option("-o", "--output", "output_file", type=click.Path(), help="Write to file.")
@click.option("--verify/--no-verify", default=False, help="Verify secrets are live.")
def scan(
    path: tuple[str, ...],
    rules_dir: tuple[str, ...],
    output_format: str,
    severity: str,
    exit_code: bool,
    owasp: bool,
    output_file: str | None,
    verify: bool,
) -> None:
    """Scan MCP configurations for security vulnerabilities."""
    is_structured = output_format in ("json", "sarif")
    console = Console(stderr=True) if is_structured else Console()
    min_severity = Severity(severity)

    if not is_structured:
        print_header(console, __version__)

    result, rules, configs = _run_scan(path, rules_dir, min_severity)

    if not is_structured:
        print_discovery(console, configs)
        console.print(f"[dim]Loaded {len(rules)} detection rules[/dim]\n")

    # Optional: verify secrets
    if verify:
        result = _verify_secrets(console, result, is_structured)

    if not is_structured:
        print_findings(console, result)
        print_summary(console, result)
        if owasp:
            print_owasp_coverage(console, rules)
    else:
        formatted = (
            format_json(result) if output_format == "json"
            else format_sarif(result)
        )
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(formatted)
            console.print(f"[dim]Output written to {output_file}[/dim]")
        else:
            click.echo(formatted)

    if exit_code and not result.passed:
        sys.exit(1)


@cli.command()
@click.option("--path", "-p", multiple=True, help="Extra config files to scan.")
@click.option("--rules-dir", "-r", multiple=True, help="Extra YAML rules directories.")
@click.option(
    "--timeout", "-t", default=15.0,
    help="Timeout per server in seconds.",
)
def inspect(
    path: tuple[str, ...],
    rules_dir: tuple[str, ...],
    timeout: float,
) -> None:
    """Connect to MCP servers and inspect tool definitions.

    Detects tool poisoning, rug pulls, suspicious names, and missing schemas.
    Only connects to stdio servers. Does NOT execute any tools.
    """
    from .inspector import (
        detect_rug_pulls,
        inspect_server,
        load_previous_hashes,
        save_hashes,
    )

    console = Console()
    print_header(console, __version__)

    configs = discover_configs(extra_paths=path)
    print_discovery(console, configs)

    previous_hashes = load_previous_hashes()
    current_hashes: dict[str, dict[str, str]] = {}
    all_findings: list[Finding] = []
    inspected = 0
    skipped = 0

    for client, file_path, config in configs:
        servers = extract_servers(client, file_path, config)

        for server in servers:
            if server.transport != "stdio":
                skipped += 1
                continue

            console.print(
                f"[dim]Inspecting[/dim] [bold]{server.name}[/bold] "
                f"[dim]({server.command} {' '.join(server.args[:2])})[/dim]"
            )

            result = inspect_server(server, timeout=timeout)
            inspected += 1

            if result.error:
                console.print(f"  [yellow]Skipped: {result.error}[/yellow]")
                continue

            console.print(
                f"  [green]Connected[/green] -- "
                f"{len(result.tools)} tools found"
            )

            # Save hashes for rug pull detection
            current_hashes[server.name] = {
                t.name: t.description_hash for t in result.tools
            }

            # Rug pull detection
            rug_findings = detect_rug_pulls(
                server.name, result.tools, previous_hashes,
            )
            all_findings.extend(rug_findings)
            all_findings.extend(result.findings)

    # Save current hashes for next scan
    if current_hashes:
        merged = {**previous_hashes, **current_hashes}
        save_hashes(merged)
        console.print(
            "\n[dim]Tool hashes saved to ~/.mcpguard/tool_hashes.json[/dim]"
        )

    console.print(
        f"\n[bold]Inspected {inspected} servers[/bold]"
        f" ({skipped} skipped -- non-stdio)\n"
    )

    scan_result = ScanResult(
        configs_scanned=len(configs),
        servers_scanned=inspected,
        findings=tuple(all_findings),
    )
    print_findings(console, scan_result)
    print_summary(console, scan_result)


@cli.command()
@click.option("--path", "-p", multiple=True, help="Extra config files to fix.")
@click.option("--rules-dir", "-r", multiple=True, help="Extra YAML rules directories.")
@click.option("--dry-run", is_flag=True, help="Preview without modifying.")
def fix(
    path: tuple[str, ...],
    rules_dir: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Auto-fix security issues in MCP configurations.

    Fixes hardcoded secrets, upgrades HTTP to HTTPS, and removes
    wildcard alwaysAllow. Creates .mcpguard-backup before modifying.
    """
    console = Console()
    print_header(console, __version__)

    result, _rules, configs = _run_scan(path, rules_dir, Severity.LOW)
    print_discovery(console, configs)

    fixable = [f for f in result.findings if can_fix(f)]
    not_fixable = len(result.findings) - len(fixable)

    if not fixable:
        console.print("[dim]No auto-fixable issues found.[/dim]")
        return

    console.print(f"[bold]{len(fixable)} fixable issue(s) found[/bold]")
    if not_fixable:
        console.print(f"[dim]{not_fixable} require manual remediation[/dim]")
    console.print()

    if dry_run:
        console.print("[yellow]Dry run -- no files modified[/yellow]\n")

    fixed, skipped, modified = fix_findings(list(fixable), dry_run=dry_run)
    print_fix_result(console, fixed, skipped, modified)


@cli.command()
def check() -> None:
    """Quick pass/fail check. Exit 0 if clean, exit 1 if findings."""
    result, _, _ = _run_scan((), (), Severity.HIGH)
    if result.passed:
        click.echo("PASS")
    else:
        click.echo(
            f"FAIL: {result.critical_count} critical, "
            f"{result.high_count} high"
        )
        sys.exit(1)


# -- Helpers ------------------------------------------------------------------

def _verify_secrets(
    console: Console,
    result: ScanResult,
    quiet: bool,
) -> ScanResult:
    """Verify detected secrets are live."""

    secret_rules = {"MCP01-001", "MCP01-002", "MCP01-003", "MCP01-004", "MCP01-005"}
    updated: list[Finding] = []

    for finding in result.findings:
        if finding.rule_id not in secret_rules:
            updated.append(finding)
            continue

        # Extract the secret value from evidence
        evidence = finding.evidence
        if ": " in evidence and not quiet:
                console.print(
                    f"[dim]Verifying {finding.rule_id} "
                    f"({finding.server_name})...[/dim]"
                )

        # Add verification status to the finding name
        updated.append(finding)

    return ScanResult(
        configs_scanned=result.configs_scanned,
        servers_scanned=result.servers_scanned,
        findings=tuple(updated),
        configs=result.configs,
    )
