"""
Run history management and cross-run vulnerability analytics.

Stores and retrieves run records from a persistent JSONL history file or from
a dedicated VCS orphan branch (trivy-bot/history).
"""
from __future__ import annotations

import json
import uuid
import base64
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

import requests


@dataclass
class RunRecord:
    run_id: str
    timestamp: str
    artifact_name: str
    provider: str
    severity_threshold: str
    cves_fixed: List[str]
    cves_skipped: List[str]
    unfixable_cves: List[str]
    pr_url: Optional[str] = None
    dry_run: bool = False
    verification_passed: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RunRecord:
        # Filter unknown keys to avoid errors on schema evolution
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


class HistoryManager:
    """Manages history records stored in JSONL format locally or via VCS API."""

    def __init__(self, config: dict):
        self.config = config
        self.history_cfg = config.get("history", {})
        self.enabled = self.history_cfg.get("enabled", True)
        self.branch_name = self.history_cfg.get("branch", "trivy-bot/history")
        self.vcs_cfg = config.get("vcs", {})

    def append_local(self, record: RunRecord, path: str | Path) -> Path:
        """Append a record to a local JSONL file."""
        file_path = Path(path).resolve()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with file_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict()) + "\n")
        return file_path

    def load_local(self, path: str | Path, last_n: Optional[int] = None) -> List[RunRecord]:
        """Load records from a local JSONL file."""
        file_path = Path(path).resolve()
        if not file_path.exists():
            return []

        records = []
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    records.append(RunRecord.from_dict(data))
                except json.JSONDecodeError:
                    continue

        if last_n and last_n > 0:
            records = records[-last_n:]
        return records

    def append(self, record: RunRecord) -> bool:
        """
        Save a run record. If VCS token & repo are configured, attempts to write
        to the trivy-bot/history branch via REST API. Also logs locally if history.path is set.
        """
        if not self.enabled:
            return False

        local_path = self.history_cfg.get("path")
        if local_path:
            self.append_local(record, local_path)

        token_env = self.vcs_cfg.get("token_env", "VCS_TOKEN")
        token = self._get_env(token_env)
        repo = self.vcs_cfg.get("repo")
        vcs_provider = self.vcs_cfg.get("provider", "github").lower()

        if not token or not repo:
            # Cannot push to remote history without VCS settings
            return False

        try:
            if vcs_provider == "github":
                return self._github_append(record, repo, token)
            elif vcs_provider == "gitlab":
                return self._gitlab_append(record, repo, token)
        except Exception:
            return False

        return False

    def load(self, last_n: Optional[int] = None) -> List[RunRecord]:
        """
        Load history records from VCS branch if configured, otherwise fallback to local path.
        """
        token_env = self.vcs_cfg.get("token_env", "VCS_TOKEN")
        token = self._get_env(token_env)
        repo = self.vcs_cfg.get("repo")
        vcs_provider = self.vcs_cfg.get("provider", "github").lower()

        if token and repo:
            try:
                if vcs_provider == "github":
                    records = self._github_load(repo, token)
                    if records:
                        if last_n and last_n > 0:
                            return records[-last_n:]
                        return records
                elif vcs_provider == "gitlab":
                    records = self._gitlab_load(repo, token)
                    if records:
                        if last_n and last_n > 0:
                            return records[-last_n:]
                        return records
            except Exception:
                pass

        local_path = self.history_cfg.get("path")
        if local_path:
            return self.load_local(local_path, last_n=last_n)

        return []

    # ------------------------------------------------------------------
    # Analytics Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def detect_recurring(records: List[RunRecord], window: int = 2) -> List[str]:
        """
        Detect CVEs that have appeared in at least `window` consecutive runs.
        Returns a sorted list of recurring CVE IDs.
        """
        if len(records) < window:
            return []

        recent_runs = records[-window:]
        # Get set of all CVEs reported in each run (fixed + skipped + unfixable)
        all_cves_per_run = []
        for r in recent_runs:
            run_cves = set(r.cves_fixed) | set(r.cves_skipped) | set(r.unfixable_cves)
            all_cves_per_run.append(run_cves)

        # Intersection across all runs in window
        recurring = set.intersection(*all_cves_per_run) if all_cves_per_run else set()
        return sorted(list(recurring))

    @staticmethod
    def compute_mttr(records: List[RunRecord]) -> Optional[float]:
        """
        Compute Mean Time To Remediate (MTTR) in days across all fixed CVEs.
        MTTR = average difference between first appearance and fixed run timestamp.
        """
        cve_first_seen: Dict[str, datetime] = {}
        durations: List[float] = []

        # Sort records by timestamp
        def parse_ts(ts_str: str) -> datetime:
            try:
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                return datetime.now(timezone.utc)

        sorted_records = sorted(records, key=lambda r: parse_ts(r.timestamp))

        for r in sorted_records:
            ts = parse_ts(r.timestamp)
            all_cves = set(r.cves_fixed) | set(r.cves_skipped) | set(r.unfixable_cves)
            
            for cve in all_cves:
                if cve not in cve_first_seen:
                    cve_first_seen[cve] = ts

            for cve in r.cves_fixed:
                if cve in cve_first_seen:
                    first_ts = cve_first_seen[cve]
                    diff_days = (ts - first_ts).total_seconds() / 86400.0
                    durations.append(diff_days)

        if not durations:
            return None

        return round(sum(durations) / len(durations), 2)

    # ------------------------------------------------------------------
    # VCS API Internals
    # ------------------------------------------------------------------

    def _github_append(self, record: RunRecord, repo: str, token: str) -> bool:
        url = f"https://api.github.com/repos/{repo}/contents/history.jsonl"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }

        # Try to fetch existing history file from branch
        sha = None
        existing_content = ""
        resp = requests.get(url, params={"ref": self.branch_name}, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            sha = data.get("sha")
            existing_content = base64.b64decode(data.get("content", "")).decode("utf-8")
        elif resp.status_code == 404:
            # Need to check if branch exists, or create it if not
            self._github_ensure_branch(repo, token)
        else:
            resp.raise_for_status()

        new_line = json.dumps(record.to_dict()) + "\n"
        updated_content = existing_content + new_line
        encoded_content = base64.b64encode(updated_content.encode("utf-8")).decode("utf-8")

        payload = {
            "message": f"chore: update vulnerability remediation history [{record.run_id[:8]}]",
            "content": encoded_content,
            "branch": self.branch_name,
        }
        if sha:
            payload["sha"] = sha

        put_resp = requests.put(url, json=payload, headers=headers, timeout=15)
        put_resp.raise_for_status()
        return True

    def _github_ensure_branch(self, repo: str, token: str) -> None:
        """Ensure orphan branch or branch from base_branch exists on GitHub."""
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        # Check if branch exists
        ref_url = f"https://api.github.com/repos/{repo}/git/ref/heads/{self.branch_name}"
        resp = requests.get(ref_url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return

        # Get sha of base_branch
        base_branch = self.vcs_cfg.get("base_branch", "main")
        base_url = f"https://api.github.com/repos/{repo}/git/ref/heads/{base_branch}"
        base_resp = requests.get(base_url, headers=headers, timeout=15)
        base_resp.raise_for_status()
        sha = base_resp.json()["object"]["sha"]

        # Create branch
        create_url = f"https://api.github.com/repos/{repo}/git/refs"
        payload = {"ref": f"refs/heads/{self.branch_name}", "sha": sha}
        create_resp = requests.post(create_url, json=payload, headers=headers, timeout=15)
        create_resp.raise_for_status()

    def _github_load(self, repo: str, token: str) -> List[RunRecord]:
        url = f"https://api.github.com/repos/{repo}/contents/history.jsonl"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        resp = requests.get(url, params={"ref": self.branch_name}, headers=headers, timeout=15)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        content = base64.b64decode(resp.json().get("content", "")).decode("utf-8")
        records = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(RunRecord.from_dict(json.loads(line)))
            except Exception:
                continue
        return records

    def _gitlab_append(self, record: RunRecord, repo: str, token: str) -> bool:
        from urllib.parse import quote
        project_encoded = quote(str(repo), safe="")
        gitlab_url = self.vcs_cfg.get("gitlab_url", "https://gitlab.com").rstrip("/")
        file_path_encoded = quote("history.jsonl", safe="")
        
        url = f"{gitlab_url}/api/v4/projects/{project_encoded}/repository/files/{file_path_encoded}"
        headers = {"PRIVATE-TOKEN": token}

        new_line = json.dumps(record.to_dict()) + "\n"

        # Check if file exists
        resp = requests.get(url, params={"ref": self.branch_name}, headers=headers, timeout=15)
        if resp.status_code == 200:
            existing_content = base64.b64decode(resp.json().get("content", "")).decode("utf-8")
            payload = {
                "branch": self.branch_name,
                "content": existing_content + new_line,
                "commit_message": f"chore: update vulnerability history [{record.run_id[:8]}]",
            }
            put_resp = requests.put(url, json=payload, headers=headers, timeout=15)
            put_resp.raise_for_status()
        elif resp.status_code == 404:
            payload = {
                "branch": self.branch_name,
                "content": new_line,
                "commit_message": f"chore: initialize vulnerability history [{record.run_id[:8]}]",
            }
            post_resp = requests.post(url, json=payload, headers=headers, timeout=15)
            post_resp.raise_for_status()
        else:
            resp.raise_for_status()
        return True

    def _gitlab_load(self, repo: str, token: str) -> List[RunRecord]:
        from urllib.parse import quote
        project_encoded = quote(str(repo), safe="")
        gitlab_url = self.vcs_cfg.get("gitlab_url", "https://gitlab.com").rstrip("/")
        file_path_encoded = quote("history.jsonl", safe="")
        
        url = f"{gitlab_url}/api/v4/projects/{project_encoded}/repository/files/{file_path_encoded}"
        headers = {"PRIVATE-TOKEN": token}
        resp = requests.get(url, params={"ref": self.branch_name}, headers=headers, timeout=15)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        content = base64.b64decode(resp.json().get("content", "")).decode("utf-8")
        records = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(RunRecord.from_dict(json.loads(line)))
            except Exception:
                continue
        return records

    @staticmethod
    def _get_env(env_var: str) -> str:
        import os
        return os.environ.get(env_var, "")
