# Architecture

Understand the internal pipeline architecture, LLM patch generation engine, and automated remediation workflow of trivy-remediation-agent.

---

## Remediation Pipeline

The following diagram illustrates how the remediation agent fits into automated CI/CD security workflows:

```
CI/CD Pipeline
│
├── Build Stage          → docker build
│
├── Trivy Scan Stage     → trivy image --format json -o trivy-report.json
│
└── Auto-Remediation Stage  ← trivy-remediation-agent
        │
        ├── 1. Parse        trivy-report.json
        ├── 2. Filter       by severity (default: HIGH+)
        ├── 3. Analyze      LLM reads vulns + Dockerfile/manifests
        │                   and generates exact search→replacement patches
        ├── 4. Apply        patches to Dockerfile, requirements.txt, etc.
        ├── 5. Commit       on a new branch
        └── 6. Open PR      for human review & approval before merge
```

---

## Supported Vulnerability Fixes

The agent automatically analyzes and remediates vulnerabilities across multiple package ecosystems:

| Vulnerability Class | Files Modified | Remediation Example |
|---|---|---|
| **OS packages (Debian/Ubuntu)** | `Dockerfile` | Adds `apt-get install libssl1.1=1.1.1w-0+deb11u1` |
| **OS packages (Alpine)** | `Dockerfile` | Adds `apk add --no-cache libssl=3.x.y` |
| **Python packages** | `requirements.txt`, `pyproject.toml`, `Pipfile` | Bumps `requests==2.28.2` → `requests>=2.31.0` |
| **Node.js packages** | `package.json` | Updates `"word-wrap": "^1.2.4"` |
| **Go modules** | `go.mod` | Updates module version |

> [!NOTE]
> Vulnerabilities with **no upstream fix** are documented directly in the generated Pull Request body for visibility.

---

## Component Layout

```
trivy-remediation-agent/
├── src/
│   ├── main.py              CLI entry point (Click: remediate & scan-report subcommands)
│   ├── orchestrator.py      Pipeline coordinator
│   ├── report_parser.py     Trivy JSON v2 parser → typed Vulnerability objects
│   ├── llm_analyzer.py      Provider-agnostic analyzer — returns a RemediationPlan
│   ├── patcher.py           Applies search→replace patches to files on disk
│   ├── git_handler.py       Branch, commit, push, and open PR/MR
│   ├── history.py           Run record tracking & VCS branch persistence
│   ├── reporter.py          HTML trend dashboard generator
│   └── providers/
│       ├── __init__.py      Provider factory (get_provider)
│       ├── base.py          BaseLLMProvider abstract interface
│       ├── claude_provider.py   Anthropic Claude SDK backend
│       └── gemini_provider.py   Google GenAI SDK backend
├── config/
│   └── config.yaml          Default configuration
├── ci/                      Pipeline integration templates
├── tests/                   Unit and integration test suites
├── Dockerfile               Containerized agent runner
└── requirements.txt
```

---

## LLM Integration Details

The agent sends the configured LLM provider:

1. The list of filtered vulnerabilities (CVE ID, affected package, installed version, fixed version, and severity level).
2. The exact contents of target manifests (`Dockerfile`, `requirements.txt`, `package.json`, `go.mod`, etc.).

The LLM returns a structured JSON payload validated against a Pydantic `RemediationPlan` model:

```json
{
  "changes": [
    {
      "file_path": "Dockerfile",
      "search": "FROM python:3.9-slim",
      "replacement": "FROM python:3.9-slim\nRUN apt-get update && apt-get install -y --no-install-recommends libssl1.1=1.1.1w-0+deb11u1 && rm -rf /var/lib/apt/lists/*",
      "cves": ["CVE-2023-2975", "CVE-2023-3817"],
      "reasoning": "Pins libssl1.1 to the patched Debian version"
    },
    {
      "file_path": "requirements.txt",
      "search": "requests==2.28.2",
      "replacement": "requests>=2.31.0",
      "cves": ["CVE-2023-32681"],
      "reasoning": "Updates requests to fix the Proxy-Authorization header leak"
    }
  ],
  "unfixable": [
    {
      "cve_id": "CVE-2023-45853",
      "package": "zlib1g",
      "severity": "CRITICAL",
      "reason": "No fix available yet in Debian repositories"
    }
  ],
  "summary": "2 file changes address 3 CVEs. 1 CVE has no upstream fix."
}
```

The `Patcher` component applies these exact string replacements. A `.trivy-backup` file is created for every modified file and automatically cleaned up once the Git commit succeeds.
