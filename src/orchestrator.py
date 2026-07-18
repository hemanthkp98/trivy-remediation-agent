"""
Main orchestration logic — ties together parsing, analysis, patching, and git.
"""
from __future__ import annotations

import os
import textwrap
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .git_handler import GitHandler
from .llm_analyzer import LLMAnalyzer, RemediationPlan
from .patcher import PatchResult, Patcher
from .report_parser import ReportParser, VulnerabilityReport

console = Console()


class Orchestrator:
    """
    End-to-end pipeline:
      1. Parse the Trivy report
      2. Filter vulnerabilities by severity
      3. Analyze with Claude → get a RemediationPlan
      4. Apply patches to the repository
      5. Commit + push + open a PR/MR
    """

    def __init__(self, config: dict, repo_path: str | Path, dry_run: bool = False):
        self.config = config
        self.repo_path = Path(repo_path).resolve()
        self.dry_run = dry_run or config.get("dry_run", False)
        self.min_severity = config.get("min_severity", "HIGH")

    def run(self, report_path: str | Path) -> dict:
        """
        Execute the full remediation pipeline.
        Returns a summary dict with keys: pr_url, cves_fixed, cves_skipped, dry_run.
        """
        # ── 1. Parse ────────────────────────────────────────────────────
        console.rule("[bold cyan]Step 1: Parsing Trivy report")
        report = ReportParser.parse(report_path)
        console.print(
            f"  Artifact  : [bold]{report.artifact_name}[/bold]\n"
            f"  Total CVEs: {report.total_count}  |  Fixable: {report.fixable_count}"
        )

        # ── 2. Filter ───────────────────────────────────────────────────
        filtered = report.filter_by_severity(self.min_severity)
        if not filtered:
            console.print(
                f"\n[green]No fixable vulnerabilities at or above {self.min_severity} severity.[/green]"
            )
            return {"pr_url": None, "cves_fixed": [], "cves_skipped": [], "dry_run": self.dry_run}

        self._print_vuln_table(filtered)

        # ── 3. Analyze with LLM ─────────────────────────────────────────
        console.rule("[bold cyan]Step 2: Analyzing with Claude")
        console.print(f"  Model : {self.config.get('llm', {}).get('model', 'claude-opus-4-6')}")
        console.print(f"  Sending {len(filtered)} vulnerabilities for analysis...")

        analyzer = LLMAnalyzer(self.config)
        plan: RemediationPlan = analyzer.analyze(report, filtered, self.repo_path)

        console.print(f"\n  [green]Plan received[/green]: {len(plan.changes)} change(s), "
                      f"{len(plan.unfixable)} unfixable")
        if plan.summary:
            console.print(Panel(plan.summary, title="LLM Summary", border_style="dim"))

        if not plan.changes:
            console.print("[yellow]LLM found no actionable changes. Exiting.[/yellow]")
            return {"pr_url": None, "cves_fixed": [], "cves_skipped": [], "dry_run": self.dry_run}

        # ── 4. Apply patches ────────────────────────────────────────────
        console.rule("[bold cyan]Step 3: Applying patches")
        patcher = Patcher(self.repo_path)
        patch_result: PatchResult = patcher.apply(plan)

        cves_fixed = [
            cve
            for change in plan.changes
            if change.file_path in patch_result.applied
            for cve in change.cves
        ]
        cves_skipped = [s["cves"] for s in patch_result.skipped]

        if patch_result.applied:
            console.print(f"  [green]Patched files[/green]: {', '.join(patch_result.applied)}")
        if patch_result.skipped:
            console.print(f"  [yellow]Skipped changes[/yellow]:")
            for skip in patch_result.skipped:
                console.print(f"    - {skip['file']}: {skip['reason']}")

        if self.dry_run:
            console.rule("[bold yellow]DRY RUN — no git operations performed")
            patcher.restore_backups()
            return {
                "pr_url": None,
                "cves_fixed": cves_fixed,
                "cves_skipped": cves_skipped,
                "dry_run": True,
                "changes": [c.model_dump() for c in plan.changes],
            }

        if not patch_result.applied:
            console.print("[red]No patches were successfully applied. Nothing to commit.[/red]")
            return {"pr_url": None, "cves_fixed": [], "cves_skipped": cves_skipped, "dry_run": False}

        # ── 5. Git operations ───────────────────────────────────────────
        console.rule("[bold cyan]Step 4: Git — commit & push")
        git = GitHandler(self.config, self.repo_path)

        branch = git.create_branch()
        console.print(f"  Branch: [bold]{branch}[/bold]")

        git.stage_files(patch_result.applied)
        git.commit()
        git.push(branch)
        patcher.remove_backups()

        # ── 6. Open PR/MR ───────────────────────────────────────────────
        console.rule("[bold cyan]Step 5: Opening Pull Request")
        pr_title = self._build_pr_title(len(cves_fixed))
        pr_body = self._build_pr_body(plan, patch_result, report.artifact_name)

        pr_data = git.open_pull_request(branch, pr_title, pr_body)
        pr_url = pr_data.get("html_url") or pr_data.get("web_url") or "N/A"

        console.print(f"\n  [bold green]PR created:[/bold green] {pr_url}")

        self._maybe_notify_slack(pr_url, pr_title, cves_fixed)

        return {
            "pr_url": pr_url,
            "cves_fixed": cves_fixed,
            "cves_skipped": cves_skipped,
            "dry_run": False,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _print_vuln_table(self, vulns) -> None:
        table = Table(title=f"Fixable vulnerabilities (≥ {self.min_severity})", show_lines=True)
        table.add_column("CVE", style="bold")
        table.add_column("Severity")
        table.add_column("Package")
        table.add_column("Installed")
        table.add_column("Fixed In")
        table.add_column("Target")

        severity_color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}

        for v in sorted(vulns, key=lambda x: -x.severity_level):
            color = severity_color.get(v.severity, "white")
            table.add_row(
                v.vuln_id,
                f"[{color}]{v.severity}[/{color}]",
                v.pkg_name,
                v.installed_version,
                v.fixed_version or "",
                v.target,
            )
        console.print(table)

    def _build_pr_title(self, count: int) -> str:
        template = self.config.get("vcs", {}).get(
            "pr_title", "fix: auto-remediate {count} Trivy vulnerabilities"
        )
        return template.replace("{count}", str(count))

    def _build_pr_body(
        self,
        plan: RemediationPlan,
        patch_result: PatchResult,
        artifact_name: str,
    ) -> str:
        cves_in_plan = []
        for change in plan.changes:
            if change.file_path in patch_result.applied:
                cves_in_plan.extend(change.cves)

        lines = [
            "## Automated Vulnerability Remediation",
            "",
            f"**Image / artifact:** `{artifact_name}`",
            "",
            "This PR was generated automatically by [trivy-remediation-agent](https://github.com/your-org/trivy-remediation-agent) "
            "after a Trivy vulnerability scan detected fixable CVEs.",
            "",
            "### Changes Made",
            "",
        ]

        for change in plan.changes:
            if change.file_path in patch_result.applied:
                lines.append(f"- **`{change.file_path}`** — {change.reasoning}")
                for cve in change.cves:
                    lines.append(f"  - Fixes `{cve}`")

        if patch_result.skipped:
            lines += [
                "",
                "### Skipped (could not auto-patch)",
                "",
            ]
            for skip in patch_result.skipped:
                lines.append(f"- `{skip['file']}`: {skip['reason']}")

        if plan.unfixable:
            lines += [
                "",
                "### No Fix Available",
                "",
            ]
            for u in plan.unfixable:
                lines.append(f"- `{u.cve_id}` ({u.severity}) — {u.package}: {u.reason}")
                if u.workaround:
                    lines.append(f"  - Workaround: {u.workaround}")

        lines += [
            "",
            "---",
            "",
            "**Review checklist:**",
            "- [ ] Review the diff to ensure version changes are safe",
            "- [ ] Run the full test suite",
            "- [ ] Re-run Trivy scan on the rebuilt image to confirm CVEs are resolved",
        ]

        return "\n".join(lines)

    def _maybe_notify_slack(self, pr_url: str, pr_title: str, cves: list[str]) -> None:
        webhook_env = self.config.get("notifications", {}).get("slack_webhook_env", "SLACK_WEBHOOK_URL")
        webhook = os.environ.get(webhook_env, "")
        if not webhook:
            return

        import requests as req
        payload = {
            "text": (
                f":shield: *Trivy Remediation PR opened*\n"
                f"*{pr_title}*\n"
                f"Fixed CVEs: `{'`, `'.join(cves)}`\n"
                f"<{pr_url}|View PR>"
            )
        }
        try:
            req.post(webhook, json=payload, timeout=10)
        except Exception:
            pass  # Slack notification is best-effort
