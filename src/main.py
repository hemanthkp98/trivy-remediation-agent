"""
trivy-remediation-agent — CLI entry point.

Usage:
  python -m src.main remediate --report trivy-report.json --repo /path/to/repo
  python -m src.main scan-report --output report.html

Backward-compatible usage:
  python -m src.main --report trivy-report.json --repo /path/to/repo
"""
from __future__ import annotations

import sys
import webbrowser
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console

from .orchestrator import Orchestrator
from .history import HistoryManager, RunRecord
from .reporter import Reporter

console = Console()

DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "config.yaml"


def load_config(config_path: str | Path) -> dict:
    path = Path(config_path)
    if not path.exists():
        console.print(f"[yellow]Config file not found at {path}; using defaults.[/yellow]")
        return {}
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


@click.group(invoke_without_command=False)
def cli() -> None:
    """trivy-remediation-agent — Automated vulnerability remediation & trend reporting tool."""
    pass


@cli.command("remediate")
@click.option(
    "--report", "-r",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the Trivy JSON report (output of `trivy image --format json`).",
)
@click.option(
    "--repo", "-R",
    default=".",
    show_default=True,
    type=click.Path(exists=True, file_okay=False),
    help="Path to the repository root containing Dockerfile / manifest files.",
)
@click.option(
    "--config", "-c",
    default=str(DEFAULT_CONFIG),
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Path to the YAML configuration file.",
)
@click.option(
    "--severity", "-s",
    default=None,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    help="Override the minimum severity from config (default: HIGH).",
)
@click.option(
    "--provider", "-p",
    default=None,
    type=click.Choice(["claude", "gemini"], case_sensitive=False),
    help="LLM provider to use (overrides config). 'claude' requires ANTHROPIC_API_KEY; "
         "'gemini' requires GEMINI_API_KEY.",
)
@click.option(
    "--dry-run", "-n",
    is_flag=True,
    default=False,
    help="Analyze and patch files locally but skip git operations and PR creation.",
)
@click.option(
    "--verify-command", "-v",
    default=None,
    help="Command to verify code correctness (e.g. 'pytest'). Override config setting.",
)
@click.option(
    "--max-retries",
    default=None,
    type=int,
    help="Max verification self-healing retries. Override config setting.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(dir_okay=False),
    help="Path to write per-run HTML summary report.",
)
def remediate(
    report: str,
    repo: str,
    config: str,
    severity: str | None,
    provider: str | None,
    dry_run: bool,
    verify_command: str | None,
    max_retries: int | None,
    output: str | None,
) -> None:
    """
    Automatically remediate vulnerabilities found by Trivy.
    """
    cfg = load_config(config)

    if severity:
        cfg["min_severity"] = severity.upper()

    if provider:
        cfg.setdefault("llm", {})["provider"] = provider.lower()

    if dry_run:
        cfg["dry_run"] = True

    if verify_command is not None:
        cfg.setdefault("verification", {})["command"] = verify_command

    if max_retries is not None:
        cfg.setdefault("verification", {})["max_retries"] = max_retries

    active_provider = cfg.get("llm", {}).get("provider", "claude")
    active_model = cfg.get("llm", {}).get("model", "(default)")

    console.rule("[bold blue]trivy-remediation-agent")
    console.print(f"  Report   : {report}")
    console.print(f"  Repo     : {repo}")
    console.print(f"  Provider : [bold cyan]{active_provider}[/bold cyan]  model={active_model}")
    console.print(f"  Severity : {cfg.get('min_severity', 'HIGH')}")
    console.print(f"  Dry run  : {cfg.get('dry_run', False)}")
    if cfg.get("verification", {}).get("command"):
        console.print(f"  Verify   : {cfg['verification']['command']} (max_retries={cfg['verification'].get('max_retries', 3)})\n")
    else:
        console.print("  Verify   : Disabled\n")

    orchestrator = Orchestrator(cfg, repo_path=repo, dry_run=cfg.get("dry_run", False))

    try:
        result = orchestrator.run(report)
    except Exception as exc:
        console.print(f"\n[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    # Optional per-run HTML output
    if output:
        run_rec = result.get("run_record")
        records = [run_rec] if isinstance(run_rec, RunRecord) else []
        html = Reporter.generate(records)
        out_file = Reporter.save(html, output)
        console.print(f"  Report   : [bold green]{out_file}[/bold green]")

    console.rule("[bold blue]Done")
    if result.get("pr_url"):
        console.print(f"  PR URL   : [bold green]{result['pr_url']}[/bold green]")
    if result.get("cves_fixed"):
        console.print(f"  CVEs fixed  : {', '.join(result['cves_fixed'])}")
    if result.get("cves_skipped"):
        flat = [c for group in result["cves_skipped"] for c in (group if isinstance(group, list) else [group])]
        console.print(f"  CVEs skipped: {', '.join(flat)}")
    if result.get("dry_run"):
        console.print("  [yellow](Dry run — no commits or PRs created)[/yellow]")


@cli.command("scan-report")
@click.option(
    "--output", "-o",
    default="./trivy-remediation-report.html",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Path to write the HTML dashboard report.",
)
@click.option(
    "--config", "-c",
    default=str(DEFAULT_CONFIG),
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Path to the YAML configuration file.",
)
@click.option(
    "--last", "-l",
    default=None,
    type=int,
    help="Limit report to the last N runs.",
)
@click.option(
    "--open", "open_browser",
    is_flag=True,
    default=False,
    help="Open the HTML report in the default browser.",
)
@click.option(
    "--push",
    is_flag=True,
    default=False,
    help="Push latest-report.html to the trivy-bot/history branch.",
)
def scan_report(
    output: str,
    config: str,
    last: int | None,
    open_browser: bool,
    push: bool,
) -> None:
    """
    Generate an HTML trend dashboard from remediation run history.
    """
    cfg = load_config(config)
    mgr = HistoryManager(cfg)
    records = mgr.load(last_n=last)

    if not records:
        console.print("[yellow]No history records found.[/yellow]")

    inline_chartjs = cfg.get("history", {}).get("inline_chartjs", False)
    html = Reporter.generate(records, inline_chartjs=inline_chartjs)
    out_path = Reporter.save(html, output)
    console.print(f"[bold green]Report generated:[/bold green] {out_path}")

    if push:
        pushed = Reporter.push_to_branch(html, cfg)
        if pushed:
            console.print("  [green]Pushed latest-report.html to trivy-bot/history branch[/green]")
        else:
            console.print("  [yellow]Failed to push report to VCS branch (check VCS_TOKEN and config)[/yellow]")

    if open_browser:
        webbrowser.open(f"file://{out_path}")


def main() -> None:
    # Shim for backward compatibility: if first arg is not a subcommand name or --help, prepend 'remediate'
    known_commands = {"remediate", "scan-report", "--help", "-h"}
    args = sys.argv[1:]
    if args and args[0] not in known_commands:
        sys.argv.insert(1, "remediate")
    cli()


if __name__ == "__main__":
    main()
