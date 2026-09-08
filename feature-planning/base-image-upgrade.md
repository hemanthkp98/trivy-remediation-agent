# Feature: Intelligent Base Image Upgrade (Root-Cause OS Remediation)

> **Status:** `DONE`  
> **Priority:** `P0`  
> **Project:** `trivy-remediation-agent`  
> **Parent Feature:** `none`  
> **Part:** `Standalone`  
> **Depends On:** `none`  
> **Target Branch:** `feat/base-image-upgrade`  
> **Requested:** 2026-09-07  
> **Completed:** 2026-09-07  

---

## Context & Motivation

When scanning container images, **80–90% of reported vulnerabilities originate from outdated operating system packages inside the base image** (e.g. Debian, Ubuntu, Alpine packages in `python:3.9-slim`, `node:18-alpine`, or `ubuntu:20.04`).

Currently, `LLMAnalyzer` instructs LLM providers (Claude/Gemini) with the following guideline in `src/llm_analyzer.py`:
```text
For OS packages (debian/ubuntu/alpine/redhat): insert a RUN command immediately after
the relevant FROM line in the Dockerfile to install pinned, patched versions.
Example: RUN apt-get update && apt-get install -y --no-install-recommends libssl1.1=1.1.1w-0+deb11u1 && rm -rf /var/lib/apt/lists/*
```

In real-world DevSecOps workflows, this symptom-patching approach suffers from critical operational failure modes:
1. **Repository Mirror Pruning (HTTP 404s):** Upstream Debian/Ubuntu/Alpine security repositories periodically archive or prune obsolete minor package revisions. Hardcoding pinned versions like `libssl1.1=1.1.1w-0+deb11u1` rapidly breaks future image builds with `404 Not Found` errors.
2. **Layer & Image Size Bloat:** Injecting multi-line `RUN apt-get update && apt-get install` commands bloats image size, adds unnecessary filesystem layers, and increases container build times.
3. **Treating Symptoms, Not Root Cause:** An outdated base image (e.g. `python:3.9.12-slim` released in 2022) accumulates dozens of known OS CVEs. Patching them one-by-one creates messy Dockerfiles and high code review friction.
4. **Clean Single-Line Fix:** Upgrading the base image tag in the `FROM` line (e.g., `python:3.9.12-slim` → `python:3.9.21-slim`) resolves the entire batch of base OS vulnerabilities in a single, clean, idiomatic diff.

This feature introduces an **Intelligent Base Image Upgrade** engine into `trivy-remediation-agent`. The agent will parse Dockerfile `FROM` lines, correlate them with OS vulnerabilities detected in container scan reports, suggest semver-compatible patch tag bumps, instruct the LLM to prioritize `FROM` line upgrades over package injection, and fall back to targeted package pinning only when a base image bump is unavailable or leaves residual CVEs.

---

## Requirements

### Must Have (P0)

- [x] **Base Image Parsing & Detection (`src/base_image.py`)**:
  - Implement a dedicated `BaseImageParser` class to inspect Dockerfiles and extract all `FROM` lines:
    - Support single-stage and multi-stage Dockerfiles (`FROM <image>[:<tag>] [AS <stage>]`).
    - Support platform flags (e.g. `FROM --platform=linux/amd64 python:3.9-slim`).
    - Parse image reference components into structured dataclass:
      ```python
      @dataclass
      class BaseImageRef:
          raw_line: str
          image: str          # e.g. "python", "library/node", "ghcr.io/org/repo"
          tag: str            # e.g. "3.9.12-slim", "18-alpine", "latest"
          stage: Optional[str] = None
          platform: Optional[str] = None
      ```
    - Correlate Trivy report `Target` OS metadata (e.g. `python:3.9.12-slim (debian 11.6)`, `alpine 3.17`) with the corresponding Dockerfile `FROM` stage.

- [x] **Semver & Tag Upgrade Suggestion Engine (`src/base_image.py`)**:
  - Implement `BaseImageResolver` that evaluates potential safe upgrade candidates for known official images:
    - **Patch Upgrade Strategy (`strategy="patch"`, default):** Detects numeric semantic versions in tags and suggests updating the patch component within the same minor release family (e.g. `3.9.12-slim` → `3.9.21-slim`, `18.14.0-alpine` → `18.20.7-alpine`).
    - **Distribution Codename Refresh (`strategy="patch"`):** Identifies base OS codenames in tags (e.g. `bullseye` → `bookworm`) and suggests modern supported Debian/Ubuntu releases when running on end-of-life distributions.
    - Provide a safe, offline tag inference mechanism and extensible candidate provider so unit tests and air-gapped environments function deterministically without requiring live network access to Docker Hub.

- [x] **LLM Prompt Enhancement for Root-Cause Remediation (`src/llm_analyzer.py`)**:
  - Update `SYSTEM_PROMPT` in `src/llm_analyzer.py`:
    - Prioritize root-cause `FROM` line upgrades when remediating `os-pkgs` vulnerabilities.
    - Rule: When a Dockerfile has base image OS vulnerabilities, replace the outdated `FROM <image>:<old_tag>` line with `FROM <image>:<new_tag>` rather than adding `RUN apt-get install`.
    - Rule: Retain `RUN apt-get / apk` commands strictly as a secondary fallback for residual CVEs that cannot be fixed by bumping the base image tag.
  - In `LLMAnalyzer._build_prompt()`, pass detected base image references and recommended upgrade candidates under a dedicated `Base Image Context` section so the LLM has exact tag candidates to use.

- [x] **Configuration & CLI Controls (`config/config.yaml`, `src/main.py`)**:
  - Add `base_image` section to `config/config.yaml`:
    ```yaml
    base_image:
      enabled: true
      strategy: "patch"               # "patch" (same minor) | "minor"
      fallback_to_package_pin: true   # allow RUN apt-get if base bump insufficient
    ```
  - Add CLI flags to `remediate` command in `src/main.py`:
    - `--base-image-upgrade / --no-base-image-upgrade` (default: true from config).
    - `--base-image-strategy [patch|minor]` (default: "patch").

- [x] **Orchestration & Verification Loop Integration (`src/orchestrator.py`)**:
  - Pass base image options into `LLMAnalyzer`.
  - In `Orchestrator.run()`, detect when a `FileChange` modifies a Dockerfile `FROM` line.
  - Highlight root-cause remediation in Rich console output and in the generated PR summary table:
    ```markdown
    ### 🐳 Base Image Upgrades
    | File | Original Base Image | Upgraded Base Image | Target OS CVEs Resolved |
    |---|---|---|---|
    | `Dockerfile` | `python:3.9.12-slim` | `python:3.9.21-slim` | CVE-2023-2975, CVE-2023-3817 |
    ```
  - Leverage the existing verification loop (`verification.command`): If `docker build .` or test verification fails on the new base image tag, the self-healing loop automatically invokes `analyze_correction()` to fall back or adjust the tag.

- [x] **Unit and Integration Tests (`tests/test_base_image.py`)**:
  - 100% test coverage for:
    1. Parsing standard, multi-stage, and platform-prefixed `FROM` lines.
    2. Tag upgrade suggestions across Python, Node, Alpine, and Debian/Ubuntu base images.
    3. LLM prompt generation with base image upgrade suggestions included.
    4. Successful search-and-replace application to `Dockerfile` via `Patcher`.
    5. Fallback behavior when `base_image.enabled: false`.

### Should Have (P1)

- [ ] Multi-stage Dockerfile awareness: identify builder stages (e.g. `golang:1.20 AS builder`) vs runtime stages (e.g. `alpine:3.17 AS runner`) and suggest targeted upgrades for the stage containing the reported CVEs.

### Must NOT Do (Guardrails)

- Do NOT make live unauthenticated HTTP/Docker Hub registry calls in unit tests; all test fixtures must run completely offline.
- Do NOT break existing language-package remediation logic for `pip` (`requirements.txt`), `npm` (`package.json`), or `gomod` (`go.mod`).
- Do NOT remove or modify existing test suites in `tests/test_verification_loop.py`, `tests/test_history.py`, `tests/test_patcher_resilience.py`, or `tests/test_reporter.py`.
- Do NOT merge directly into `main` — all changes must be committed to the dedicated feature branch `feat/base-image-upgrade`.
- Do NOT include author, co-author, or contributor trailers in git commits (`Co-authored-by:`, etc.).

---

## Technical Spec

### Affected Files / Modules

| File / Module | Change Description |
|---|---|
| `src/base_image.py` | **[NEW]** Base image parser, `BaseImageRef` dataclass, tag upgrade analysis, and version comparison utilities. |
| `src/llm_analyzer.py` | **[MODIFY]** Update `SYSTEM_PROMPT` to prioritize base image upgrades for OS packages; include base image candidates in prompt context. |
| `src/orchestrator.py` | **[MODIFY]** Integrate base image resolver into pipeline, track base image changes, and enhance PR body with root-cause summary. |
| `src/main.py` | **[MODIFY]** Add `--base-image-upgrade / --no-base-image-upgrade` and `--base-image-strategy` CLI options. |
| `config/config.yaml` | **[MODIFY]** Add default `base_image` configuration block (`enabled: true`, `strategy: "patch"`, `fallback_to_package_pin: true`). |
| `tests/test_base_image.py` | **[NEW]** Comprehensive test suite for parsing, tag upgrade resolution, prompt context generation, and fallback handling. |

### Architecture Notes

- Follow the modular pattern established by `src/report_parser.py` and `src/patcher.py`.
- `BaseImageParser` should use regex patterns that match Dockerfile syntax standard:
  ```python
  FROM_PATTERN = re.compile(
      r"^FROM\s+(?:--platform=\S+\s+)?([^\s:]+)(?::([^\s]+))?(?:\s+AS\s+([^\s]+))?",
      re.IGNORECASE | re.MULTILINE
  )
  ```
- Tag version parsing should handle common Docker tag conventions:
  - `<version>-<variant>` (e.g. `3.9.12-slim`, `18.15.0-alpine3.17`, `1.20.4-bookworm`)
  - `<version>` (e.g. `20.04`, `3.18`)
- The output from `LLMAnalyzer` remains a standard Pydantic `RemediationPlan` with `FileChange` entries. For a base image upgrade, `FileChange.file_path` is `Dockerfile`, `FileChange.search` is `FROM python:3.9.12-slim`, and `FileChange.replacement` is `FROM python:3.9.21-slim`. This ensures full compatibility with the existing `Patcher` without altering its core search-and-replace mechanism.

### New Dependencies (if any)

| Package | Version Constraint | Reason |
|---|---|---|
| `packaging` | `>=23.0,<25.0` | Robust semantic version parsing and comparison for Docker image tags (usually already available in standard Python environments). |

---

## Acceptance Criteria

The agent MUST verify ALL of these before marking the feature `DONE`:

- [x] `ruff check .` passes with zero errors
- [x] `ruff format --check .` passes with zero errors
- [x] `mypy src/` passes with zero errors
- [x] `pytest tests/ -v --tb=short` passes with 100% success rate
- [x] New unit tests in `tests/test_base_image.py` pass and cover all P0 requirements
- [x] No existing tests in `tests/` are broken or skipped
- [x] Backward compatibility is preserved: scanning non-Docker projects or reports without OS vulnerabilities functions normally without regression
- [x] Feature branch is pushed to origin (NOT merged to `main`)
- [x] This file is updated: Status set to `DONE`, Completed date filled

---

## Examples / References

### Example 1: Input Dockerfile with Outdated Base Image
```dockerfile
FROM python:3.9.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["python", "app.py"]
```

### Example 2: Trivy Report Snippet (OS Package CVEs in Container)
```json
{
  "Target": "python:3.9.12-slim (debian 11.3)",
  "Class": "os-pkgs",
  "Type": "debian",
  "Vulnerabilities": [
    {
      "VulnerabilityID": "CVE-2023-2975",
      "PkgName": "libssl1.1",
      "InstalledVersion": "1.1.1n-0+deb11u1",
      "FixedVersion": "1.1.1w-0+deb11u1",
      "Severity": "HIGH"
    },
    {
      "VulnerabilityID": "CVE-2023-3817",
      "PkgName": "libssl1.1",
      "InstalledVersion": "1.1.1n-0+deb11u1",
      "FixedVersion": "1.1.1w-0+deb11u1",
      "Severity": "MEDIUM"
    }
  ]
}
```

### Example 3: Generated RemediationPlan with Root-Cause Upgrade
```json
{
  "changes": [
    {
      "file_path": "Dockerfile",
      "search": "FROM python:3.9.12-slim",
      "replacement": "FROM python:3.9.21-slim",
      "cves": ["CVE-2023-2975", "CVE-2023-3817"],
      "reasoning": "Upgraded python base image to 3.9.21-slim, resolving Debian libssl1.1 vulnerabilities at the root cause without layer bloat or brittle package pinning."
    }
  ],
  "unfixable": [],
  "summary": "Upgraded base image python:3.9.12-slim to python:3.9.21-slim in Dockerfile to remediate 2 OS-level vulnerabilities."
}
```

---

## Agent Instructions

> [!IMPORTANT]
> Follow these steps exactly:
>
> 1. Read the project's `.agents/AGENTS.md` and `CLAUDE.md` in `projects/trivy-remediation-agent` for full context.
> 2. Switch to / create branch `feat/base-image-upgrade` in the `trivy-remediation-agent` repository.
> 3. Implement ONLY P0 requirements. Do NOT implement P1 or optional features.
> 4. Adhere to the Minimal Diff Principle: do not touch files outside Affected Files or refactor working code.
> 5. Write unit tests in `tests/test_base_image.py` alongside implementation.
> 6. Run ALL lint and test commands listed in Acceptance Criteria (fix errors only in authored code).
> 7. Commit with conventional commits: `feat(remediation): add intelligent base image upgrade for OS vulnerabilities`.
> 8. Do NOT add co-author or agent metadata in commit messages.
> 9. Push the feature branch to origin.
> 10. Update this file: set Status to `DONE` and fill the Completed date.
