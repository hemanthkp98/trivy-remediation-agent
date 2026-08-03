"""
Unit tests for history management and analytics logic.
"""
from pathlib import Path
import tempfile
import json

from src.history import RunRecord, HistoryManager


def test_run_record_serialization():
    rec = RunRecord(
        run_id="test-run-123",
        timestamp="2026-08-03T12:00:00Z",
        artifact_name="myapp:latest",
        provider="gemini",
        severity_threshold="HIGH",
        cves_fixed=["CVE-2023-1111", "CVE-2023-2222"],
        cves_skipped=["CVE-2023-3333"],
        unfixable_cves=["CVE-2023-4444"],
        pr_url="https://github.com/org/repo/pull/1",
        dry_run=False,
        verification_passed=True,
    )

    data = rec.to_dict()
    assert data["run_id"] == "test-run-123"
    assert data["cves_fixed"] == ["CVE-2023-1111", "CVE-2023-2222"]

    loaded = RunRecord.from_dict(data)
    assert loaded.run_id == rec.run_id
    assert loaded.cves_fixed == rec.cves_fixed
    assert loaded.pr_url == rec.pr_url


def test_history_manager_local_append_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        history_file = Path(tmpdir) / "history.jsonl"
        mgr = HistoryManager({"history": {"enabled": True, "path": str(history_file)}})

        rec1 = RunRecord(
            run_id="run-1",
            timestamp="2026-08-01T10:00:00Z",
            artifact_name="app:v1",
            provider="gemini",
            severity_threshold="HIGH",
            cves_fixed=["CVE-2023-1000"],
            cves_skipped=[],
            unfixable_cves=[],
        )
        rec2 = RunRecord(
            run_id="run-2",
            timestamp="2026-08-02T10:00:00Z",
            artifact_name="app:v1",
            provider="gemini",
            severity_threshold="HIGH",
            cves_fixed=["CVE-2023-2000"],
            cves_skipped=[],
            unfixable_cves=[],
        )

        mgr.append_local(rec1, history_file)
        mgr.append_local(rec2, history_file)

        loaded = mgr.load_local(history_file)
        assert len(loaded) == 2
        assert loaded[0].run_id == "run-1"
        assert loaded[1].run_id == "run-2"

        # Check last_n filtering
        loaded_last = mgr.load_local(history_file, last_n=1)
        assert len(loaded_last) == 1
        assert loaded_last[0].run_id == "run-2"


def test_detect_recurring_cves():
    rec1 = RunRecord(
        run_id="run-1",
        timestamp="2026-08-01T10:00:00Z",
        artifact_name="app:v1",
        provider="gemini",
        severity_threshold="HIGH",
        cves_fixed=[],
        cves_skipped=["CVE-RECURRING-1", "CVE-ONEOFF"],
        unfixable_cves=[],
    )
    rec2 = RunRecord(
        run_id="run-2",
        timestamp="2026-08-02T10:00:00Z",
        artifact_name="app:v1",
        provider="gemini",
        severity_threshold="HIGH",
        cves_fixed=[],
        cves_skipped=["CVE-RECURRING-1"],
        unfixable_cves=[],
    )

    recurring = HistoryManager.detect_recurring([rec1, rec2], window=2)
    assert recurring == ["CVE-RECURRING-1"]


def test_compute_mttr():
    rec1 = RunRecord(
        run_id="run-1",
        timestamp="2026-08-01T00:00:00Z",
        artifact_name="app:v1",
        provider="gemini",
        severity_threshold="HIGH",
        cves_fixed=[],
        cves_skipped=["CVE-FIXABLE"],
        unfixable_cves=[],
    )
    rec2 = RunRecord(
        run_id="run-2",
        timestamp="2026-08-03T00:00:00Z",  # 2 days later
        artifact_name="app:v1",
        provider="gemini",
        severity_threshold="HIGH",
        cves_fixed=["CVE-FIXABLE"],
        cves_skipped=[],
        unfixable_cves=[],
    )

    mttr = HistoryManager.compute_mttr([rec1, rec2])
    assert mttr == 2.0
