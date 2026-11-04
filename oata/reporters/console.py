"""Rich console reporter for OWASP Agentic Threat Auditor (OATA).

Emits clean terminal vulnerability tables and executive breach metrics.
"""

from __future__ import annotations

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from oata.core.models import AuditReport, Severity


def render_console_report(report: AuditReport, console: Console | None = None) -> None:
    """Render color-coded audit summary and findings to terminal."""
    con = console or Console()

    # Header Panel
    con.print()
    banner = Text("OWASP AGENTIC THREAT AUDITOR (OATA)", style="bold cyan")
    banner.append(f"  v0.1-Alpha\n", style="dim white")
    banner.append(f"Target: ", style="bold")
    banner.append(f"{report.target_name} ({report.target_endpoint or 'in-memory mock'})  ", style="yellow")
    banner.append(f"Session: ", style="bold")
    banner.append(f"{report.session_id}  ", style="dim")
    banner.append(f"Duration: ", style="bold")
    banner.append(f"{report.duration_ms:.1f}ms", style="green")

    con.print(Panel(banner, box=ROUNDED, border_style="cyan"))

    # Findings Table
    if report.findings:
        table = Table(
            title="Identified Excessive Agency & Safety Violations",
            box=ROUNDED,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("Finding ID", style="dim", width=22)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Threat Taxonomy", width=26)
        table.add_column("Description & Evidence", justify="left")

        for f in report.findings:
            if f.severity == Severity.CRITICAL:
                sev_text = Text(f.severity.value, style="bold white on red")
            elif f.severity == Severity.HIGH:
                sev_text = Text(f.severity.value, style="bold red")
            elif f.severity == Severity.MEDIUM:
                sev_text = Text(f.severity.value, style="bold yellow")
            else:
                sev_text = Text(f.severity.value, style="cyan")

            tool_invoked = f.evidence.get("tool_name", "N/A")
            params = str(f.evidence.get("parameters", {}))
            details = (
                f"[bold]{f.title}[/bold]\n"
                f"{f.description}\n"
                f"[yellow]Invoked Tool:[/yellow] {tool_invoked} | [yellow]Params:[/yellow] {params}\n"
                f"[dim green]Remediation:[/dim green] {f.remediation}"
            )

            table.add_row(f.id, sev_text, f.category.value, details)

        con.print(table)
    else:
        con.print(
            Panel(
                Text("No Excessive Agency or tool escalation vulnerabilities detected.", style="bold green"),
                box=ROUNDED,
                border_style="green",
            )
        )

    # Summary Metrics Table
    summary = Table(box=ROUNDED, show_header=False)
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", justify="right")

    summary.add_row("Vectors Tested", str(report.total_vectors))
    summary.add_row("Passed (Resistant)", f"[green]{report.passed_vectors}[/green]")
    summary.add_row("Failed (Vulnerable)", f"[red]{report.failed_vectors}[/red]")
    summary.add_row("Critical Severity", f"[bold red]{report.critical_count}[/bold red]")
    summary.add_row("High Severity", f"[red]{report.high_count}[/red]")
    summary.add_row("Medium Severity", f"[yellow]{report.medium_count}[/yellow]")

    con.print(Panel(summary, title="Audit Execution Summary", box=ROUNDED, width=45))
    con.print()

