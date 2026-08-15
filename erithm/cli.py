"""
Erithm CLI — command-line interface for taint analysis.

Provides commands for:
    - ``erithm analyze <trace-file>`` — Analyze an exported trace file.
    - ``erithm watch`` — Attach to an OTel collector in real-time.
    - ``erithm policy validate <file>`` — Validate a policy file.
    - ``erithm policy show`` — Display the effective policy.
    - ``erithm version`` — Show version info.

Uses Rich for beautiful terminal output with color-coded verdict
severity indicators.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from erithm import __version__
from erithm.config import load_config, ErithmConfig, VerdictMode
from erithm.middleware.interceptor import ErithmInterceptor
from erithm.policy.loader import PolicyLoader
from erithm.verdict.models import VerdictType, AnalysisResult

console = Console()

# CLI styling constants
_VERDICT_STYLES = {
    VerdictType.ALLOW: ("✓ ALLOW", "green"),
    VerdictType.LOG: ("📝 LOG", "dim"),
    VerdictType.WARN: ("⚠ WARN", "yellow"),
    VerdictType.REQUIRE_CONFIRMATION: ("🔒 CONFIRM", "yellow bold"),
    VerdictType.BLOCK: ("✗ BLOCK", "red bold"),
}

_BANNER = r"""
[bold cyan]
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   ███████╗██████╗ ██╗████████╗██╗  ██╗███╗   ███╗        ║
  ║   ██╔════╝██╔══██╗██║╚══██╔══╝██║  ██║████╗ ████║        ║
  ║   █████╗  ██████╔╝██║   ██║   ███████║██╔████╔██║        ║
  ║   ██╔══╝  ██╔══██╗██║   ██║   ██╔══██║██║╚██╔╝██║        ║
  ║   ███████╗██║  ██║██║   ██║   ██║  ██║██║ ╚═╝ ██║        ║
  ║   ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝        ║
  ║                                                           ║
  ║   Taint-Analysis Firewall for LLM Tool-Calling Agents    ║
  ╚═══════════════════════════════════════════════════════════╝
[/bold cyan]"""


def _render_result(result: AnalysisResult) -> None:
    """Render an analysis result to the console with Rich formatting.

    Args:
        result: The AnalysisResult to display.
    """
    # Summary panel
    verdict_text, verdict_style = _VERDICT_STYLES[result.overall_verdict]
    summary = Text()
    summary.append(f"Overall Verdict: ", style="bold")
    summary.append(verdict_text, style=verdict_style)
    summary.append(f"\n\nTrace ID: ", style="bold")
    summary.append(result.trace_id[:16] if result.trace_id else "N/A")
    summary.append(f"\nTool Calls: ", style="bold")
    summary.append(str(result.total_tool_calls))
    summary.append(f"\nTainted Calls: ", style="bold")
    summary.append(str(result.tainted_calls))
    summary.append(f"\nViolations: ", style="bold")
    summary.append(str(result.violations_found))
    summary.append(f"\nAnalysis Time: ", style="bold")
    summary.append(f"{result.analysis_time_ms:.1f}ms")

    console.print(Panel(summary, title="[bold]Analysis Summary[/bold]", border_style="cyan", box=box.DOUBLE))

    # Verdicts table
    if result.verdicts:
        table = Table(
            title="Verdicts",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Verdict", style="bold", width=12)
        table.add_column("Tool", width=20)
        table.add_column("Confidence", justify="right", width=12)
        table.add_column("Classifier", width=12)
        table.add_column("Policy Rule", width=15)
        table.add_column("Reason", width=40)

        for verdict in result.verdicts:
            v_text, v_style = _VERDICT_STYLES[verdict.verdict_type]
            table.add_row(
                Text(v_text, style=v_style),
                verdict.tool_name,
                f"{verdict.confidence:.0%}",
                verdict.classifier,
                verdict.policy_rule,
                verdict.reason[:80] + "..." if len(verdict.reason) > 80 else verdict.reason,
            )

        console.print(table)
    else:
        console.print("[green]No violations detected — trace is clean.[/green]")


@click.group()
@click.option("--config", "config_path", type=click.Path(exists=False), help="Path to erithm.yaml config file.")
@click.option("--log-level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]), default=None, help="Override log level.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output.")
@click.pass_context
def main(ctx: click.Context, config_path: str | None, log_level: str | None, quiet: bool) -> None:
    """Erithm — Taint-analysis firewall for LLM tool-calling agents.

    Detects prompt injection via tool output before it reaches
    privileged sinks like send_email, execute_shell, or transfer_funds.
    """
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = Path(config_path) if config_path else None
    ctx.obj["log_level"] = log_level
    ctx.obj["quiet"] = quiet

    if not quiet:
        console.print(_BANNER)


@main.command()
@click.argument("trace_file", type=click.Path(exists=True))
@click.option("--mode", type=click.Choice(["block", "warn", "log"]), default=None, help="Override verdict mode.")
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None, help="Custom policy file.")
@click.option("--output", "-o", type=click.Choice(["rich", "json"]), default="rich", help="Output format.")
@click.pass_context
def analyze(ctx: click.Context, trace_file: str, mode: str | None, policy_path: str | None, output: str) -> None:
    """Analyze an exported trace file for prompt injection.

    TRACE_FILE is the path to a JSON/JSONL/OTLP trace export file.
    """
    config_path = ctx.obj.get("config_path")
    log_level = ctx.obj.get("log_level")
    quiet = ctx.obj.get("quiet", False)

    # Suppress logging in quiet mode
    if quiet:
        logging.basicConfig(level=logging.ERROR)

    config = load_config(config_path)

    # Override verdict mode if specified
    if mode:
        # Create new config with overridden mode
        config = ErithmConfig(
            policy_path=Path(policy_path) if policy_path else config.policy_path,
            verdict_mode=VerdictMode(mode),
            classifier_mode=config.classifier_mode,
            otel=config.otel,
            lm_judge=config.lm_judge,
            log_level=log_level or config.log_level,
            redact_content=config.redact_content,
        )

    interceptor = ErithmInterceptor(config=config)
    result = interceptor.analyze_file(trace_file)

    if output == "json":
        # JSON output for programmatic use
        json_output = {
            "trace_id": result.trace_id,
            "overall_verdict": result.overall_verdict.value,
            "violations_found": result.violations_found,
            "total_tool_calls": result.total_tool_calls,
            "tainted_calls": result.tainted_calls,
            "analysis_time_ms": result.analysis_time_ms,
            "verdicts": [
                {
                    "type": v.verdict_type.value,
                    "tool_name": v.tool_name,
                    "confidence": v.confidence,
                    "reason": v.reason,
                    "policy_rule": v.policy_rule,
                    "owasp_ref": v.owasp_ref,
                }
                for v in result.verdicts
            ],
        }
        click.echo(json.dumps(json_output, indent=2))
    else:
        _render_result(result)

    # Exit with non-zero code if violations found in block mode
    if result.has_blocks:
        sys.exit(1)


@main.command()
@click.option("--endpoint", default="127.0.0.1:4317", help="OTel collector gRPC endpoint.")
@click.pass_context
def watch(ctx: click.Context, endpoint: str) -> None:
    """Attach to an OTel collector and analyze traces in real-time.

    Listens for incoming spans on the gRPC endpoint and runs taint
    analysis as traces complete.
    """
    console.print(f"[bold cyan]Watching for traces on {endpoint}...[/bold cyan]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    # TODO: Implement real-time gRPC listener
    # For v1, this is scaffolded. The full implementation requires
    # an async gRPC server to receive OTLP spans.
    console.print(
        "[yellow]Real-time watch mode is scaffolded for v1. "
        "Use 'erithm analyze <file>' for offline analysis.[/yellow]"
    )
    console.print(
        "[dim]Implementation requires OpenTelemetry Collector setup. "
        "See README.md for instructions.[/dim]"
    )


@main.group()
def policy() -> None:
    """Manage security policies."""
    pass


@policy.command("validate")
@click.argument("policy_file", type=click.Path(exists=True))
def policy_validate(policy_file: str) -> None:
    """Validate a YAML policy file.

    Checks the policy file for syntax errors, unknown fields, and
    invalid rule configurations.
    """
    loader = PolicyLoader()

    try:
        loaded_policy = loader.load_file(policy_file)
        console.print(f"[green]✓ Policy is valid[/green]")
        console.print(f"  Version: {loaded_policy.version}")
        console.print(f"  Sources: {len(loaded_policy.sources)} rules")
        console.print(f"  Sinks:   {len(loaded_policy.sinks)} rules")

        # Show summary table
        if loaded_policy.sinks:
            table = Table(title="Sink Rules", box=box.SIMPLE)
            table.add_column("Name", style="bold")
            table.add_column("Pattern")
            table.add_column("Action")
            table.add_column("OWASP Ref")

            for sink in loaded_policy.sinks:
                action_style = "red" if sink.action == "block" else "yellow"
                table.add_row(
                    sink.name,
                    sink.pattern,
                    Text(sink.action.value, style=action_style),
                    sink.owasp_ref or "-",
                )
            console.print(table)

    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗ Policy validation failed: {e}[/red]")
        sys.exit(1)


@policy.command("show")
@click.pass_context
def policy_show(ctx: click.Context) -> None:
    """Display the effective policy (default + overrides)."""
    config_path = ctx.obj.get("config_path") if ctx.obj else None
    config = load_config(config_path)

    loader = PolicyLoader()
    try:
        loaded_policy = loader.load_file(config.policy_path)
    except (FileNotFoundError, ValueError):
        loaded_policy = loader.load_default()

    console.print(Panel(f"Policy v{loaded_policy.version}", title="[bold]Effective Policy[/bold]", border_style="cyan"))

    # Sources
    src_table = Table(title="Untrusted Sources", box=box.ROUNDED)
    src_table.add_column("Name", style="bold")
    src_table.add_column("Pattern")
    src_table.add_column("Taint Level")

    for src in loaded_policy.sources:
        src_table.add_row(src.name, src.pattern, src.taint_level)
    console.print(src_table)

    # Sinks
    sink_table = Table(title="Privileged Sinks", box=box.ROUNDED)
    sink_table.add_column("Name", style="bold")
    sink_table.add_column("Pattern")
    sink_table.add_column("Action")
    sink_table.add_column("Min Taint")
    sink_table.add_column("OWASP")

    for sink in loaded_policy.sinks:
        sink_table.add_row(
            sink.name,
            sink.pattern,
            sink.action.value,
            sink.min_taint_level,
            sink.owasp_ref or "-",
        )
    console.print(sink_table)


@main.command()
def version() -> None:
    """Show Erithm version and system info."""
    import platform
    import sys

    info = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info.add_column("Key", style="bold cyan")
    info.add_column("Value")

    info.add_row("Erithm", f"v{__version__}")
    info.add_row("Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    info.add_row("Platform", platform.platform())

    console.print(info)


if __name__ == "__main__":
    main()
