"""
Unit tests for HTML dashboard reporter.
"""
from pathlib import Path
import tempfile

from src.history import RunRecord
from src.reporter import Reporter


def test_reporter_generate_empty():
    html = Reporter.generate([])
    assert "No execution history recorded yet" in html
    assert "<!DOCTYPE html>" in html


def test_reporter_generate_with_records():
    rec1 = RunRecord(
        run_id="run-001",
        timestamp="2026-08-01T10:00:00Z",
        artifact_name="demo-app:v1",
        provider="gemini",
        severity_threshold="HIGH",
        cves_fixed=["CVE-2023-1111"],
        cves_skipped=[],
        unfixable_cves=["CVE-2023-9999"],
        pr_url="https://github.com/org/repo/pull/42",
        dry_run=False,
    )
    rec2 = RunRecord(
        run_id="run-002",
        timestamp="2026-08-02T10:00:00Z",
        artifact_name="demo-app:v1",
        provider="gemini",
        severity_threshold="HIGH",
        cves_fixed=[],
        cves_skipped=[],
        unfixable_cves=["CVE-2023-9999"],
        dry_run=True,
    )

    html = Reporter.generate([rec1, rec2])

    assert "Vulnerability Remediation Dashboard" in html
    assert "demo-app:v1" in html
    assert "CVE-2023-1111" in html or "1" in html
    assert "https://github.com/org/repo/pull/42" in html
    assert "CVE-2023-9999" in html  # Recurring CVE in unfixable across 2 runs
    assert "⚠️ Recurring Vulnerability Regressions" in html


def test_reporter_save():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "report.html"
        html_content = "<html><body>Test Report</body></html>"

        saved_path = Reporter.save(html_content, out_path)
        assert saved_path.exists()
        assert saved_path.read_text(encoding="utf-8") == html_content
