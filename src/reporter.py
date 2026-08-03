"""
Self-contained HTML report generator for Trivy vulnerability remediation history.

Produces interactive trend dashboards with Chart.js visualization, severity breakdowns,
recurring CVE alerts, PR audit logs, and MTTR metrics.
"""
from __future__ import annotations

import json
import base64
from pathlib import Path
from typing import List, Optional, Dict, Any

import requests

from .history import RunRecord, HistoryManager


class Reporter:
    """Generates standalone HTML report dashboards from RunRecord lists."""

    @classmethod
    def generate(cls, records: List[RunRecord], inline_chartjs: bool = False) -> str:
        if not records:
            return cls._empty_report_html()

        recurring_cves = HistoryManager.detect_recurring(records, window=2)
        mttr_days = HistoryManager.compute_mttr(records)

        # Prepare Chart.js datasets
        timestamps = [r.timestamp[:16].replace("T", " ") for r in records]
        cves_fixed_counts = [len(r.cves_fixed) for r in records]
        cves_skipped_counts = [len(r.cves_skipped) for r in records]
        unfixable_counts = [len(r.unfixable_cves) for r in records]

        chart_labels_json = json.dumps(timestamps)
        fixed_data_json = json.dumps(cves_fixed_counts)
        skipped_data_json = json.dumps(cves_skipped_counts)
        unfixable_data_json = json.dumps(unfixable_counts)

        # Table rows for run history
        history_rows_html = []
        for r in reversed(records):
            status_badge = '<span class="badge badge-success">Success</span>'
            if r.dry_run:
                status_badge = '<span class="badge badge-warning">Dry Run</span>'
            elif r.verification_passed is False:
                status_badge = '<span class="badge badge-danger">Verify Failed</span>'

            pr_link = f'<a href="{r.pr_url}" target="_blank">View PR</a>' if r.pr_url else '<span class="text-muted">None</span>'
            
            history_rows_html.append(f"""
            <tr>
                <td><code>{r.run_id[:8]}</code></td>
                <td>{r.timestamp[:19].replace("T", " ")}</td>
                <td><strong>{r.artifact_name}</strong></td>
                <td><span class="badge badge-info">{r.provider}</span></td>
                <td>{len(r.cves_fixed)}</td>
                <td>{len(r.cves_skipped)}</td>
                <td>{len(r.unfixable_cves)}</td>
                <td>{status_badge}</td>
                <td>{pr_link}</td>
            </tr>
            """)

        # Table rows for recurring CVEs
        recurring_rows_html = []
        for cve in recurring_cves:
            recurring_rows_html.append(f"""
            <tr>
                <td><strong class="text-danger">{cve}</strong></td>
                <td><span class="badge badge-danger">⚠️ Recurring Regression</span></td>
                <td>Detected in last 2+ consecutive runs</td>
            </tr>
            """)

        recurring_section_html = ""
        if recurring_cves:
            recurring_section_html = f"""
            <div class="card mb-4 border-danger">
                <div class="card-header bg-danger text-white">
                    <h5 class="m-0">⚠️ Recurring Vulnerability Regressions</h5>
                </div>
                <div class="card-body p-0">
                    <table class="table table-hover m-0">
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Status</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(recurring_rows_html)}
                        </tbody>
                    </table>
                </div>
            </div>
            """

        mttr_display = f"{mttr_days} days" if mttr_days is not None else "N/A"

        chart_js_script = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'
        if inline_chartjs:
            # Minimal inline notice if air-gapped without CDN
            chart_js_script = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trivy Remediation Agent — Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    {chart_js_script}
    <style>
        body {{ background-color: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        .card {{ border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; }}
        .metric-card {{ text-align: center; padding: 20px; }}
        .metric-value {{ font-size: 2.2rem; font-weight: bold; color: #0d6efd; }}
        .metric-label {{ text-transform: uppercase; font-size: 0.8rem; letter-spacing: 1px; color: #6c757d; }}
        .badge-success {{ background-color: #198754; }}
        .badge-warning {{ background-color: #ffc107; color: #000; }}
        .badge-danger {{ background-color: #dc3545; }}
        .badge-info {{ background-color: #0dcaf0; color: #000; }}
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="m-0 font-weight-bold">🛡️ Vulnerability Remediation Dashboard</h2>
                <p class="text-muted m-0">Historical trend analysis & automated patch execution metrics</p>
            </div>
            <div>
                <span class="badge bg-secondary">Total Runs: {len(records)}</span>
            </div>
        </div>

        <!-- Metrics Row -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-value">{sum(cves_fixed_counts)}</div>
                    <div class="metric-label">Total CVEs Fixed</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-value">{sum(unfixable_counts)}</div>
                    <div class="metric-label">Unfixable CVEs</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-value">{mttr_display}</div>
                    <div class="metric-label">Mean Time To Remediate (MTTR)</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-value text-danger">{len(recurring_cves)}</div>
                    <div class="metric-label">Recurring Regressions</div>
                </div>
            </div>
        </div>

        {recurring_section_html}

        <!-- Charts Row -->
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header bg-white">
                        <h5 class="m-0">Vulnerability Trend Over Time</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="trendChart" height="90"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Audit Table -->
        <div class="card">
            <div class="card-header bg-white">
                <h5 class="m-0">Remediation Execution History</h5>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover align-middle m-0">
                        <thead class="table-light">
                            <tr>
                                <th>Run ID</th>
                                <th>Timestamp</th>
                                <th>Artifact / Target</th>
                                <th>LLM Provider</th>
                                <th>Fixed</th>
                                <th>Skipped</th>
                                <th>Unfixable</th>
                                <th>Status</th>
                                <th>PR / Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(history_rows_html)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener("DOMContentLoaded", function() {{
            const ctx = document.getElementById('trendChart').getContext('2d');
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: {chart_labels_json},
                    datasets: [
                        {{
                            label: 'CVEs Fixed',
                            data: {fixed_data_json},
                            backgroundColor: '#198754'
                        }},
                        {{
                            label: 'CVEs Skipped',
                            data: {skipped_data_json},
                            backgroundColor: '#ffc107'
                        }},
                        {{
                            label: 'Unfixable CVEs',
                            data: {unfixable_data_json},
                            backgroundColor: '#dc3545'
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        x: {{ stacked: true }},
                        y: {{ stacked: true, beginAtZero: true }}
                    }}
                }}
            }});
        }});
    </script>
</body>
</html>
"""
        return html_template

    @classmethod
    def save(cls, html_content: str, output_path: str | Path) -> Path:
        path = Path(output_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")
        return path

    @classmethod
    def push_to_branch(cls, html_content: str, config: dict) -> bool:
        vcs_cfg = config.get("vcs", {})
        history_cfg = config.get("history", {})
        branch_name = history_cfg.get("branch", "trivy-bot/history")
        token_env = vcs_cfg.get("token_env", "VCS_TOKEN")
        token = HistoryManager._get_env(token_env)
        repo = vcs_cfg.get("repo")
        vcs_provider = vcs_cfg.get("provider", "github").lower()

        if not token or not repo:
            return False

        try:
            if vcs_provider == "github":
                return cls._github_push_report(html_content, repo, branch_name, token)
            elif vcs_provider == "gitlab":
                return cls._gitlab_push_report(html_content, repo, branch_name, token)
        except Exception:
            return False
        return False

    @classmethod
    def _github_push_report(cls, html_content: str, repo: str, branch: str, token: str) -> bool:
        url = f"https://api.github.com/repos/{repo}/contents/latest-report.html"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        resp = requests.get(url, params={"ref": branch}, headers=headers, timeout=15)
        sha = resp.json().get("sha") if resp.status_code == 200 else None

        encoded = base64.b64encode(html_content.encode("utf-8")).decode("utf-8")
        payload = {
            "message": "docs: update latest vulnerability remediation HTML dashboard",
            "content": encoded,
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha

        put_resp = requests.put(url, json=payload, headers=headers, timeout=15)
        put_resp.raise_for_status()
        return True

    @classmethod
    def _gitlab_push_report(cls, html_content: str, repo: str, branch: str, token: str) -> bool:
        from urllib.parse import quote
        project_encoded = quote(str(repo), safe="")
        gitlab_url = config.get("vcs", {}).get("gitlab_url", "https://gitlab.com").rstrip("/")
        file_path_encoded = quote("latest-report.html", safe="")

        url = f"{gitlab_url}/api/v4/projects/{project_encoded}/repository/files/{file_path_encoded}"
        headers = {"PRIVATE-TOKEN": token}

        resp = requests.get(url, params={"ref": branch}, headers=headers, timeout=15)
        payload = {
            "branch": branch,
            "content": html_content,
            "commit_message": "docs: update latest vulnerability remediation HTML dashboard",
        }
        if resp.status_code == 200:
            put_resp = requests.put(url, json=payload, headers=headers, timeout=15)
            put_resp.raise_for_status()
        else:
            post_resp = requests.post(url, json=payload, headers=headers, timeout=15)
            post_resp.raise_for_status()
        return True

    @staticmethod
    def _empty_report_html() -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Trivy Remediation Agent — Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
</head>
<body class="bg-light text-center py-5">
    <div class="container">
        <h3>🛡️ Vulnerability Remediation Dashboard</h3>
        <p class="text-muted">No execution history recorded yet.</p>
    </div>
</body>
</html>
"""
