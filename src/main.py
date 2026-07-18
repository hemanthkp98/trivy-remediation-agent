"""
trivy-remediation-agent — CLI entry point.

Usage:
  python -m src.main --report trivy-report.json --repo /path/to/repo

Run `python -m src.main --help` for all options.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click
import yaml
from rich.console import Console

from .orchestrator import Orchestrator

console = Console()

DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "config.yaml"


def load_config(config_path: str | Path) -> dict:
    path = Path(config_path)
    if not path.exists():
        console.print(f"[yellow]Config file not found at {path}; using defaults.[/yellow]")
        return {}
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


@click.command()
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
    "--dry-run", "-n",
    is_flag=True,
    default=False,
    help="Analyze and patch files locally but skip git operations and PR creation.",
)
def main(report: str, repo: str, config: str, severity: str | None, dry_run: bool) -> None:
    """
    Automatically remediate vulnerabilities found by Trivy.

    Reads a Trivy JSON report, sends the vulnerabilities to Claude for analysis,
    applies the resulting patches to the repository, and opens a Pull Request.
    """
    cfg = load_config(config)

    if severity:
        cfg["min_severity"] = severity.upper()

    if dry_run:
        cfg["dry_run"] = True

    console.rule("[bold blue]trivy-remediation-agent")
    console.print(f"  Report : {report}")
    console.print(f"  Repo   : {repo}")
    console.print(f"  Severity threshold : {cfg.get('min_severity', 'HIGH')}")
    console.print(f"  Dry run : {cfg.get('dry_run', False)}\n")

    orchestrator = Orchestrator(cfg, repo_path=repo, dry_run=cfg.get("dry_run", False))

    try:
        result = orchestrator.run(report)
    except Exception as exc:
        console.print(f"\n[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    console.rule("[bold blue]Done")
    if result.get("pr_url"):
        console.print(f"  PR URL   : [bold green]{result['pr_url']}[/bold green]")
    if result.get("cves_fixed"):
        console.print(f"  CVEs fixed  : {', '.join(result['cves_fixed'])}")
    if result.get("cves_skipped"):
        flat = [c for group in result["cves_skipped"] for c in group]
        console.print(f"  CVEs skipped: {', '.join(flat)}")
    if result.get("dry_run"):
        console.print("  [yellow](Dry run — no commits or PRs created)[/yellow]")


if __name__ == "__main__":
    main()
