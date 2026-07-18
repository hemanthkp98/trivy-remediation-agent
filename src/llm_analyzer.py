"""
LLM-powered vulnerability analysis.

Sends grouped vulnerability data + relevant repo file contents to the
configured LLM provider, which returns a structured remediation plan
specifying exact file changes.

Supported providers: ``claude`` (default), ``gemini``.
Configure via ``config["llm"]["provider"]`` or the ``--provider`` CLI flag.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, ValidationError

from .report_parser import Vulnerability, VulnerabilityReport
from .providers import get_provider, BaseLLMProvider


# ---------------------------------------------------------------------------
# Data models for the structured LLM output
# ---------------------------------------------------------------------------

class FileChange(BaseModel):
    """A single search-and-replace operation on one file."""
    file_path: str = Field(
        description="Relative path to the file that needs to be modified"
    )
    search: str = Field(
        description=(
            "The exact text (verbatim, including newlines if multi-line) "
            "to search for in the file. Must match what is currently in the file."
        )
    )
    replacement: str = Field(
        description=(
            "The text to replace `search` with. "
            "Use \\n for newlines when adding multiple lines."
        )
    )
    cves: list[str] = Field(
        description="List of CVE IDs that this change addresses"
    )
    reasoning: str = Field(
        description="Brief explanation of why this change fixes the vulnerability"
    )


class UnfixableVuln(BaseModel):
    cve_id: str
    package: str
    severity: str
    reason: str
    workaround: Optional[str] = None


class RemediationPlan(BaseModel):
    """Complete remediation plan returned by the LLM."""
    changes: list[FileChange] = Field(
        description="Ordered list of file changes to apply"
    )
    unfixable: list[UnfixableVuln] = Field(
        default_factory=list,
        description="Vulnerabilities that cannot be auto-remediated"
    )
    summary: str = Field(
        description="Human-readable summary of what will be changed and why"
    )


# ---------------------------------------------------------------------------
# File discovery helpers
# ---------------------------------------------------------------------------

# Files to look for and include as context when analyzing vulnerabilities
CONTEXT_FILES = [
    "Dockerfile",
    "Dockerfile.prod",
    "Dockerfile.production",
    "requirements.txt",
    "requirements-base.txt",
    "requirements/base.txt",
    "requirements/production.txt",
    "Pipfile",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
]

# Map Trivy target types to the relevant manifest files
TYPE_TO_FILES: dict[str, list[str]] = {
    "pip": ["requirements.txt", "requirements-base.txt", "requirements/base.txt",
            "requirements/production.txt", "Pipfile", "pyproject.toml"],
    "pipenv": ["Pipfile"],
    "poetry": ["pyproject.toml"],
    "npm": ["package.json"],
    "yarn": ["package.json", "yarn.lock"],
    "gomod": ["go.mod"],
    "bundler": ["Gemfile"],
    "composer": ["composer.json"],
    "maven": ["pom.xml"],
    "gradle": ["build.gradle"],
    # OS package targets — Dockerfile is always relevant
    "debian": ["Dockerfile"],
    "ubuntu": ["Dockerfile"],
    "alpine": ["Dockerfile"],
    "redhat": ["Dockerfile"],
    "centos": ["Dockerfile"],
    "amazon": ["Dockerfile"],
}

MAX_FILE_CHARS = 4000  # truncate very large files to keep prompt size manageable


def discover_repo_files(repo_path: Path, target_types: set[str]) -> dict[str, str]:
    """
    Scan the repository for files relevant to the detected vulnerability types.
    Returns a dict of {relative_path: file_content}.
    """
    relevant_names: set[str] = {"Dockerfile"}
    for t in target_types:
        for fname in TYPE_TO_FILES.get(t, []):
            relevant_names.add(fname)

    contents: dict[str, str] = {}
    for name in relevant_names:
        candidate = repo_path / name
        if candidate.exists():
            text = candidate.read_text(errors="replace")
            if len(text) > MAX_FILE_CHARS:
                text = text[:MAX_FILE_CHARS] + "\n... (truncated)"
            contents[name] = text

    return contents


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert DevSecOps engineer specializing in container and application security.
Your job is to analyze Trivy vulnerability reports and produce precise, minimal file changes
that upgrade affected packages to their fixed versions — without breaking the application.

Guidelines:
- For OS packages (debian/ubuntu/alpine/redhat): insert a RUN command immediately after
  the relevant FROM line in the Dockerfile to install pinned, patched versions.
  Example: RUN apt-get update && apt-get install -y --no-install-recommends libssl1.1=1.1.1w-0+deb11u1 && rm -rf /var/lib/apt/lists/*
- For pip packages: update the version constraint in requirements.txt (or equivalent).
  Prefer `>=fixed_version` unless the file already uses exact pinning, in which case
  use `==fixed_version`.
- For npm packages: update the version in package.json.
- For go modules: update the version in go.mod using `go get` syntax in the replacement text.
- Only fix vulnerabilities that have a listed FixedVersion.
- The `search` field MUST be the exact string currently in the file (copy-paste accurate).
- Each FileChange addresses one or more related CVEs in the same package.
- Consolidate changes: if multiple CVEs in the same package are fixed by one version bump,
  emit a single FileChange listing all CVE IDs.
- Do not modify files that are not shown in the "Repository Files" section.

IMPORTANT: You MUST respond with a single valid JSON object matching this exact schema:
{
  "changes": [
    {
      "file_path": "string",
      "search": "string",
      "replacement": "string",
      "cves": ["string"],
      "reasoning": "string"
    }
  ],
  "unfixable": [
    {
      "cve_id": "string",
      "package": "string",
      "severity": "string",
      "reason": "string",
      "workaround": "string or null"
    }
  ],
  "summary": "string"
}
Do not include any prose, markdown fences, or explanation outside the JSON object.
"""


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class LLMAnalyzer:
    """
    Analyze vulnerabilities using the configured LLM provider and return
    a structured RemediationPlan.

    The provider (Claude or Gemini) is selected from ``config["llm"]["provider"]``
    or overridden via the ``--provider`` CLI flag which injects it into config
    before this class is instantiated.
    """

    def __init__(self, config: dict) -> None:
        self.provider: BaseLLMProvider = get_provider(config)
        llm_cfg = config.get("llm", {})
        self.max_tokens = int(llm_cfg.get("max_tokens", 8192))

    def analyze(
        self,
        report: VulnerabilityReport,
        filtered_vulns: list[Vulnerability],
        repo_path: Path,
    ) -> RemediationPlan:
        """
        Build the prompt, call the LLM provider, parse the JSON response
        into a validated RemediationPlan, and return it.
        """
        target_types = {v.target_type for v in filtered_vulns}
        file_contents = discover_repo_files(repo_path, target_types)
        grouped = report.group_by_target(filtered_vulns)
        prompt = self._build_prompt(report.artifact_name, grouped, file_contents)

        raw_text = self.provider.complete(SYSTEM_PROMPT, prompt, self.max_tokens)
        plan = self._parse_response(raw_text)
        return plan

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        artifact_name: str,
        grouped: dict,
        file_contents: dict[str, str],
    ) -> str:
        lines: list[str] = [
            "# Vulnerability Remediation Request",
            f"\nImage / artifact: **{artifact_name}**\n",
            "## Vulnerabilities to Fix\n",
        ]

        for (target, cls, vtype), vulns in grouped.items():
            lines.append(f"### {cls} ({vtype}) — target: `{target}`\n")
            for v in vulns:
                fv = v.fixed_version or "*(no fix available)*"
                lines.append(
                    f"- **{v.vuln_id}** | {v.severity} | "
                    f"`{v.pkg_name}` {v.installed_version} → fixed in `{fv}`  "
                )
                if v.title:
                    lines.append(f"  *{v.title}*")
            lines.append("")

        if file_contents:
            lines.append("## Repository Files\n")
            for fpath, content in file_contents.items():
                lines.append(f"### `{fpath}`\n```")
                lines.append(content)
                lines.append("```\n")
        else:
            lines.append(
                "## Repository Files\n"
                "*(No matching files were found in the repository. "
                "Generate changes for the most common file names such as "
                "`Dockerfile` and `requirements.txt`.)*\n"
            )

        lines.append(
            "## Task\n"
            "Return a complete RemediationPlan JSON with:\n"
            "- `changes`: list of FileChange objects with exact search/replacement text\n"
            "- `unfixable`: list of UnfixableVuln for CVEs with no available fix\n"
            "- `summary`: a brief human-readable summary of the changes\n"
        )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, raw_text: str) -> RemediationPlan:
        """
        Extract JSON from the LLM response and validate it into a
        RemediationPlan.  Handles optional markdown code fences.
        """
        text = raw_text.strip()

        # Strip optional ```json ... ``` fences
        fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if fence_match:
            text = fence_match.group(1)
        else:
            # Find the outermost JSON object
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                text = text[start:end]

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"LLM returned invalid JSON.\nError: {exc}\nRaw response:\n{raw_text[:500]}"
            ) from exc

        try:
            return RemediationPlan(**data)
        except ValidationError as exc:
            raise RuntimeError(
                f"LLM response did not match the RemediationPlan schema.\n"
                f"Validation errors: {exc}\nParsed data: {data}"
            ) from exc
