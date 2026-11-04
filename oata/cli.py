"""Command Line Interface for OWASP Agentic Threat Auditor (OATA)."""

from __future__ import annotations

import asyncio
import sys
from typing import Optional

import click
from rich.box import ROUNDED
from rich.console import Console
from rich.table import Table

from oata import __version__
from oata.adapters.mock import MockAgentAdapter
from oata.adapters.trace import TraceReplayAdapter
from oata.core.engine import AuditEngine, get_default_payload_suite
from oata.core.guard import TargetGuardViolationError
from oata.core.models import TargetConfig
from oata.reporters.console import render_console_report
from oata.reporters.json_reporter import export_json_report
from oata.reporters.sarif import export_sarif_report

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="oata")
def main() -> None:
    """OWASP Agentic Threat Auditor (OATA)

    Dynamic Penetration Testing & Excessive Agency Auditing Toolkit for Multi-Hop AI Agents.
    """
    pass


@main.command("version")
def version_cmd() -> None:
    """Display OATA version, license, and official OWASP project references."""
    console.print(f"[bold cyan]OWASP Agentic Threat Auditor (OATA)[/bold cyan] [green]v{__version__}[/green]")
    console.print("Classification: [bold red]Breaker[/bold red] (Dynamic Red Teaming & Penetration Testing)")
    console.print("License: Apache License 2.0")
    console.print("Project Page: [link=https://owasp.org/projects/agentic-threat-auditor]https://owasp.org/projects/agentic-threat-auditor[/link]")
    console.print("Repository:   [link=https://github.com/OWASP/Agentic-Threat-Auditor]https://github.com/OWASP/Agentic-Threat-Auditor[/link]")


@main.command("list-payloads")
def list_payloads_cmd() -> None:
    """List all registered Phase 1 offensive attack vector payloads."""
    payloads = get_default_payload_suite()
    table = Table(
        title="OATA Core Offensive Payload Suite (Phase 1: Foundation)",
        box=ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Vector ID", style="cyan", no_wrap=True)
    table.add_column("Payload Name", style="bold white")
    table.add_column("Severity", justify="center")
    table.add_column("Threat Taxonomy")

    for p in payloads:
        table.add_row(p.id, p.name, p.severity.value, p.category.value)

    console.print(table)


@main.command("demo")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["console", "json", "sarif"], case_sensitive=False),
    default="console",
    help="Report output format (default: console)",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Write report to destination file path.",
)
def demo_cmd(output_format: str, output_file: Optional[str]) -> None:
    """Run zero-dependency end-to-end simulated audit against built-in mock target."""
    console.print("[dim cyan][*] Initializing built-in mock target with intentional OWASP LLM08 flaws...[/dim cyan]")
    target = TargetConfig(name="MockVulnerableAgent", endpoint="mock://localhost", adapter_type="mock")
    adapter = MockAgentAdapter(target)
    engine = AuditEngine(target, adapter)

    try:
        report = asyncio.run(engine.run())
    except Exception as exc:
        console.print(f"[bold red]Demo execution error:[/bold red] {exc}")
        sys.exit(1)

    _dispatch_report(report, output_format, output_file)


@main.command("audit")
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target agent endpoint, URL, or JSON trace file path.",
)
@click.option(
    "--adapter",
    "-a",
    type=click.Choice(["mock", "trace"], case_sensitive=False),
    default="mock",
    help="Target adapter driver type (mock, trace).",
)
@click.option(
    "--allow-remote",
    is_flag=True,
    default=False,
    help="Bypass Safe Local Target Guard to audit remote/external endpoints.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["console", "json", "sarif"], case_sensitive=False),
    default="console",
    help="Report output format (console, json, sarif).",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Write report to destination file path.",
)
def audit_cmd(target: str, adapter: str, allow_remote: bool, output_format: str, output_file: Optional[str]) -> None:
    """Execute dynamic audit suite against an agent target or execution trace."""
    config = TargetConfig(
        name=f"AuditTarget-{target}",
        endpoint=target,
        adapter_type=adapter,
        allow_remote=allow_remote,
    )

    if adapter == "trace":
        driver = TraceReplayAdapter(config)
    else:
        driver = MockAgentAdapter(config)

    engine = AuditEngine(config, driver)

    try:
        report = asyncio.run(engine.run())
    except TargetGuardViolationError as err:
        console.print(f"[bold red]Target Guard Error:[/bold red] {err}")
        sys.exit(2)
    except Exception as exc:
        console.print(f"[bold red]Audit failure:[/bold red] {exc}")
        sys.exit(1)

    _dispatch_report(report, output_format, output_file)


def _dispatch_report(report, output_format: str, output_file: Optional[str]) -> None:
    fmt = output_format.lower()
    if fmt == "json":
        json_output = export_json_report(report, output_file)
        if not output_file:
            print(json_output)
        else:
            console.print(f"[green]Report exported in JSON format to:[/green] {output_file}")
    elif fmt == "sarif":
        sarif_output = export_sarif_report(report, output_file)
        if not output_file:
            print(sarif_output)
        else:
            console.print(f"[green]Report exported in SARIF v2.1.0 format to:[/green] {output_file}")
    else:
        render_console_report(report, console)
        if output_file:
            export_json_report(report, output_file)
            console.print(f"[dim]Copy also saved to {output_file}[/dim]")


if __name__ == "__main__":
    main()
