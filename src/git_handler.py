"""
Git operations and VCS PR/MR creation.

Supports GitHub (REST v3) and GitLab (REST v4).
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests


class GitError(Exception):
    pass


class GitHandler:
    """Manage a local git repo and open pull / merge requests on GitHub or GitLab."""

    def __init__(self, config: dict, repo_path: str | Path):
        self.repo_path = Path(repo_path).resolve()
        self.git_cfg = config.get("git", {})
        self.vcs_cfg = config.get("vcs", {})
        self.provider = self.vcs_cfg.get("provider", "github").lower()

    # ------------------------------------------------------------------
    # Local git operations
    # ------------------------------------------------------------------

    def create_branch(self, suffix: Optional[str] = None) -> str:
        """Checkout a new branch and return its name."""
        prefix = self.git_cfg.get("branch_prefix", "fix/trivy-remediation")
        ts = suffix or datetime.now().strftime("%Y%m%d-%H%M%S")
        branch_name = f"{prefix}-{ts}"
        self._git("checkout", "-b", branch_name)
        return branch_name

    def stage_files(self, files: list[str]) -> None:
        """Stage specific files."""
        for f in files:
            self._git("add", f)

    def commit(self, message: Optional[str] = None) -> None:
        """Create a commit with staged changes."""
        msg = message or self.git_cfg.get(
            "commit_message",
            "fix: auto-remediate Trivy vulnerabilities",
        )
        author_name = self.git_cfg.get("author_name", "Trivy Remediation Bot")
        author_email = self.git_cfg.get("author_email", "trivy-bot@noreply.local")

        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = author_name
        env["GIT_AUTHOR_EMAIL"] = author_email
        env["GIT_COMMITTER_NAME"] = author_name
        env["GIT_COMMITTER_EMAIL"] = author_email

        self._git("commit", "-m", msg, env=env)

    def push(self, branch_name: str) -> None:
        """Push branch to origin."""
        self._git("push", "-u", "origin", branch_name)

    # ------------------------------------------------------------------
    # PR / MR creation
    # ------------------------------------------------------------------

    def open_pull_request(
        self,
        branch_name: str,
        title: str,
        body: str,
    ) -> dict:
        """Open a PR (GitHub) or MR (GitLab) and return the API response dict."""
        if self.provider == "github":
            return self._github_create_pr(branch_name, title, body)
        elif self.provider == "gitlab":
            return self._gitlab_create_mr(branch_name, title, body)
        else:
            raise ValueError(
                f"Unknown VCS provider '{self.provider}'. "
                "Supported: github, gitlab"
            )

    def _github_create_pr(self, branch: str, title: str, body: str) -> dict:
        token = self._token()
        repo = self.vcs_cfg.get("repo", "")
        base = self.vcs_cfg.get("base_branch", "main")

        if not repo:
            raise ValueError("vcs.repo must be set (e.g. 'owner/my-repo')")

        url = f"https://api.github.com/repos/{repo}/pulls"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        payload = {"title": title, "body": body, "head": branch, "base": base}
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if self.vcs_cfg.get("auto_merge") and data.get("number"):
            self._github_enable_auto_merge(repo, data["number"], token)

        return data

    def _github_enable_auto_merge(self, repo: str, pr_number: int, token: str) -> None:
        """Enable auto-merge on a GitHub PR (requires branch protection rules)."""
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/merge"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        requests.put(url, json={"merge_method": "squash"}, headers=headers, timeout=30)

    def _gitlab_create_mr(self, branch: str, title: str, body: str) -> dict:
        token = self._token()
        project = self.vcs_cfg.get("repo", "")
        base = self.vcs_cfg.get("base_branch", "main")
        gitlab_url = self.vcs_cfg.get("gitlab_url", "https://gitlab.com").rstrip("/")

        if not project:
            raise ValueError("vcs.repo must be set (numeric project ID or 'namespace/project')")

        # URL-encode the project path if it contains slashes
        from urllib.parse import quote
        project_encoded = quote(str(project), safe="")

        url = f"{gitlab_url}/api/v4/projects/{project_encoded}/merge_requests"
        headers = {"PRIVATE-TOKEN": token}
        payload = {
            "source_branch": branch,
            "target_branch": base,
            "title": title,
            "description": body,
            "remove_source_branch": True,
        }
        if self.vcs_cfg.get("auto_merge"):
            payload["merge_when_pipeline_succeeds"] = True

        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _token(self) -> str:
        env_var = self.vcs_cfg.get("token_env", "VCS_TOKEN")
        token = os.environ.get(env_var, "")
        if not token:
            raise EnvironmentError(
                f"VCS token not found. Set the '{env_var}' environment variable."
            )
        return token

    def _git(self, *args: str, env: Optional[dict] = None) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            raise GitError(
                f"git {' '.join(args)} failed:\n{result.stderr.strip()}"
            )
        return result.stdout.strip()
