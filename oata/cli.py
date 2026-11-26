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
from oata.adapters.http import HttpAgentAdapter
from oata.adapters.mock import MockAgentAdapter
from oata.adapters.trace import TraceReplayAdapter
from oata.core.engine import AuditEngine, get_default_payload_suite, get_extended_payload_suite
from oata.core.guard import TargetGuardViolationError
from oata.core.models import TargetConfig
from oata.reporters.console import render_console_report
from oata.reporters.json_reporter import export_json_report
from oata.reporters.markdown import export_markdown_report
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
@click.option("--all", "show_all", is_flag=True, default=False, help="Include extended SSRF and credential probes.")
def list_payloads_cmd(show_all: bool) -> None:
    """List registered offensive attack vector payloads."""
    payloads = get_extended_payload_suite() if show_all else get_default_payload_suite()
    table = Table(
        title="OATA Core Offensive Payload Suite",
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
    type=click.Choice(["console", "json", "sarif", "markdown"], case_sensitive=False),
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
    type=click.Choice(["mock", "trace", "http"], case_sensitive=False),
    default="mock",
    help="Target adapter driver type (mock, trace, http).",
)
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["standard", "full"], case_sensitive=False),
    default="standard",
    help="Payload suite profile (standard=3 core vectors, full=5 vectors incl. SSRF & credential probes).",
)
@click.option(
    "--model",
    "-m",
    default="local-agent",
    help="Model identifier for chat-completions endpoints (default: local-agent).",
)
@click.option(
    "--header",
    "-H",
    "headers",
    multiple=True,
    help="Custom HTTP header in 'Key: Value' format (repeatable).",
)
@click.option(
    "--concurrency",
    "-c",
    type=int,
    default=5,
    help="Maximum concurrent payload requests (default: 5).",
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
    type=click.Choice(["console", "json", "sarif", "markdown"], case_sensitive=False),
    default="console",
    help="Report output format (console, json, sarif, markdown).",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Write report to destination file path.",
)
def audit_cmd(
    target: str,
    adapter: str,
    profile: str,
    model: str,
    headers: tuple[str, ...],
    concurrency: int,
    allow_remote: bool,
    output_format: str,
    output_file: Optional[str],
) -> None:
    """Execute dynamic audit suite against an agent target or execution trace."""
    parsed_headers = {}
    for item in headers:
        if ":" in item:
            key, value = item.split(":", 1)
            parsed_headers[key.strip()] = value.strip()

    adapter_key = adapter.lower()
    config = TargetConfig(
        name=f"AuditTarget-{target}",
        endpoint=target,
        adapter_type=adapter_key,
        allow_remote=allow_remote,
        metadata={"model": model, "headers": parsed_headers},
    )

    if adapter_key == "trace":
        driver = TraceReplayAdapter(config)
    elif adapter_key == "http":
        driver = HttpAgentAdapter(config)
    else:
        driver = MockAgentAdapter(config)

    payloads = get_extended_payload_suite() if profile.lower() == "full" else get_default_payload_suite()
    engine = AuditEngine(config, driver, payloads=payloads, concurrency=concurrency)

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
    elif fmt == "markdown":
        md_output = export_markdown_report(report, output_file)
        if not output_file:
            print(md_output)
        else:
            console.print(f"[green]Report exported in Markdown format to:[/green] {output_file}")
    else:
        render_console_report(report, console)
        if output_file:
            export_json_report(report, output_file)
            console.print(f"[dim]Copy also saved to {output_file}[/dim]")


if __name__ == "__main__":
    main()
