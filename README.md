# trivy-remediation-agent

An end-to-end automation pipeline that reads a [Trivy](https://github.com/aquasecurity/trivy) vulnerability report, uses an LLM (**Claude** or **Gemini**) to generate precise file patches, applies them to the repository, and opens a Pull Request — with zero human intervention in the fix cycle.

---

## How It Works

```
CI/CD Pipeline
│
├── Build Stage          → docker build
│
├── Trivy Scan Stage     → trivy image --format json -o trivy-report.json
│
└── Auto-Remediation Stage  ← this tool
        │
        ├── 1. Parse        trivy-report.json
        ├── 2. Filter       by severity (default: HIGH+)
        ├── 3. Analyze      LLM reads vulns + your Dockerfile/manifests
        │                   and returns exact search→replacement patches
        ├── 4. Apply        patches to Dockerfile, requirements.txt, etc.
        ├── 5. Commit       on a new branch
        └── 6. Open PR      for human review & approval before merge
```

### What the agent fixes automatically

| Vulnerability class | Files modified | Example |
|---------------------|---------------|---------|
| OS packages (Debian/Ubuntu) | `Dockerfile` | Adds `apt-get install libssl1.1=1.1.1w-0+deb11u1` |
| OS packages (Alpine) | `Dockerfile` | Adds `apk add --no-cache libssl=3.x.y` |
| Python packages | `requirements.txt`, `pyproject.toml`, `Pipfile` | Bumps `requests==2.28.2` → `requests>=2.31.0` |
| Node.js packages | `package.json` | Updates `"word-wrap": "^1.2.4"` |
| Go modules | `go.mod` | Updates module version |

Vulnerabilities with **no available fix** are listed in the PR body for human awareness.

---

## Quick Start

### Prerequisites
- Python 3.11+
- An API key for your chosen LLM provider (see [LLM Providers](#llm-providers))
- A GitHub or GitLab token with `repo` / `api` write scopes

### Installation

```bash
git clone https://github.com/hemanthkp98/trivy-remediation-agent
cd trivy-remediation-agent
pip install -r requirements.txt
cp .env.example .env
# Edit .env — add your LLM API key and VCS_TOKEN
```

### Run against a Trivy report

```bash
# 1. Scan your image with Trivy
trivy image --format json --output trivy-report.json myapp:latest

# 2. Run the agent — dry-run first to preview changes (no git ops)
python -m src.main \
  --report trivy-report.json \
  --repo /path/to/your/app \
  --dry-run

# 3. When satisfied, run for real
python -m src.main \
  --report trivy-report.json \
  --repo /path/to/your/app
```

### Run with Docker

```bash
docker build -t trivy-remediation-agent .

# With Gemini (default)
docker run --rm \
  -e GEMINI_API_KEY=$GEMINI_API_KEY \
  -e VCS_TOKEN=$VCS_TOKEN \
  -v $(pwd):/repo \
  -v $(pwd)/trivy-report.json:/report.json \
  trivy-remediation-agent \
  --report /report.json --repo /repo

# With Claude
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e VCS_TOKEN=$VCS_TOKEN \
  -v $(pwd):/repo \
  -v $(pwd)/trivy-report.json:/report.json \
  trivy-remediation-agent \
  --report /report.json --repo /repo --provider claude
```

---

## LLM Providers

The agent supports two LLM backends, switchable via config or the `--provider` CLI flag.

| Provider | Flag | Config value | API Key env var | Default model |
|----------|------|-------------|-----------------|---------------|
| Google Gemini | `--provider gemini` | `llm.provider: gemini` | `GEMINI_API_KEY` | `gemini-2.5-pro` |
| Anthropic Claude | `--provider claude` | `llm.provider: claude` | `ANTHROPIC_API_KEY` | `claude-opus-4-6` |

### Getting API Keys

- **Gemini** → [Google AI Studio](https://aistudio.google.com/apikey) (free tier available)
- **Claude** → [Anthropic Console](https://console.anthropic.com/)

### Switching Providers

**Via CLI flag** (overrides config):
```bash
python -m src.main --report trivy-report.json --repo . --provider gemini --dry-run
python -m src.main --report trivy-report.json --repo . --provider claude --dry-run
```

**Via `config/config.yaml`:**
```yaml
llm:
  provider: gemini        # "claude" | "gemini"
  model: gemini-2.5-pro   # or claude-opus-4-6, gemini-2.5-flash, etc.
```

**Via environment:**
```bash
# Gemini
export GEMINI_API_KEY=AIza...

# Claude
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Configuration

Copy `config/config.yaml` and edit as needed. Pass it with `--config`:

```yaml
min_severity: HIGH          # CRITICAL | HIGH | MEDIUM | LOW

llm:
  provider: gemini          # "claude" | "gemini"
  model: gemini-2.5-pro     # model name for the chosen provider
  max_tokens: 8192

vcs:
  provider: github          # github | gitlab
  token_env: VCS_TOKEN
  repo: "my-org/my-repo"   # GitHub: owner/repo | GitLab: project ID or path
  base_branch: main
  pr_title: "fix: auto-remediate {count} Trivy vulnerabilities"
```

All config values can also be overridden via CLI flags:

```
Options:
  -r, --report PATH       Trivy JSON report          [required]
  -R, --repo PATH         Repository root            [default: .]
  -c, --config PATH       Config file
  -s, --severity LEVEL    Min severity               [CRITICAL|HIGH|MEDIUM|LOW]
  -p, --provider NAME     LLM provider               [claude|gemini]
  -n, --dry-run           No git ops, preview only
  --help
```

---

## Setting Up Your VCS Token (GitHub / GitLab PAT)

The `VCS_TOKEN` environment variable provides the credentials required to push remediation branches, open Pull/Merge Requests, and maintain history records.

### GitHub PAT Provisioning

We recommend creating a **Fine-grained Personal Access Token (PAT)** for enhanced security:

1. Go to **Settings** → **Developer settings** → **Personal access tokens** → **Fine-grained tokens**.
2. Click **Generate new token**.
3. Select your target **Repository access** ("Only select repositories" → choose your app repository).
4. Set the following **Repository permissions**:
   - **Contents**: `Read and write` (to push branches and write history logs)
   - **Pull requests**: `Read and write` (to open remediation PRs)
5. Copy the generated token and export it as `VCS_TOKEN`.

*Note: If using Classic PATs, select the `repo` scope.*

### GitLab Token Provisioning

1. Go to **User Settings** → **Access Tokens** (or Project Access Tokens).
2. Name: `trivy-remediation-agent`.
3. Select scopes: **`api`** and **`write_repository`**.
4. Copy the token and export it as `VCS_TOKEN`.

### Storing the Token in CI/CD

- **GitHub Actions**: Add as a repository secret (`Settings` → `Secrets` → `Actions` → `VCS_TOKEN`).
- **GitLab CI**: Add as a masked CI/CD variable (`Settings` → `CI/CD` → `Variables`).

---

## History & Trend Dashboard Reporting

`trivy-remediation-agent` maintains an automated run history on a dedicated orphan branch (`trivy-bot/history`) via VCS REST API calls, avoiding ephemeral runner data loss in CI/CD pipelines.

### Generating HTML Trend Dashboards

You can generate interactive, self-contained HTML dashboards showing CVE trends, recurring regressions, MTTR (Mean Time To Remediate), and execution logs:

```bash
# Generate dashboard from recorded history
python -m src.main scan-report --output report.html --open

# Limit to the last 10 runs and push the dashboard back to the history branch
python -m src.main scan-report --last 10 --push
```

### Single-Run HTML Summary

To generate a standalone HTML report artifact for a single remediation run (useful for CI artifact upload step):

```bash
python -m src.main remediate --report trivy-report.json --repo . --output summary.html
```

---

## Architecture

```
trivy-remediation-agent/
├── src/
│   ├── main.py              CLI (Click) — entry point (remediate & scan-report)
│   ├── orchestrator.py      Pipeline coordinator
│   ├── report_parser.py     Trivy JSON v2 parser → typed Vulnerability objects
│   ├── llm_analyzer.py      Provider-agnostic analyzer — returns a RemediationPlan
│   ├── patcher.py           Applies search→replace patches to files on disk
│   ├── git_handler.py       Branch, commit, push, open PR/MR
│   ├── history.py           Run record tracking & VCS branch persistence
│   ├── reporter.py          HTML trend dashboard generator
│   └── providers/
│       ├── __init__.py      get_provider(config) factory
│       ├── base.py          BaseLLMProvider abstract interface
│       ├── claude_provider.py   Anthropic SDK (ANTHROPIC_API_KEY)
│       └── gemini_provider.py   google-genai SDK (GEMINI_API_KEY)
├── config/
│   └── config.yaml          Default configuration
├── ci/                      Ready-to-use pipeline snippets
├── tests/
│   ├── fixtures/
│   │   └── sample_trivy_report.json
│   ├── test_history.py
│   ├── test_patcher_resilience.py
│   ├── test_reporter.py
│   └── test_verification_loop.py
├── Dockerfile               Containerised agent runner
└── requirements.txt
```

### LLM Integration Details

The agent sends the configured LLM provider:
- The full list of filtered vulnerabilities (CVE ID, package, installed/fixed versions, severity)
- The content of relevant files (`Dockerfile`, `requirements.txt`, `package.json`, `go.mod`, etc.)

The LLM returns a **structured JSON `RemediationPlan`** (validated with Pydantic) containing:

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

The `Patcher` applies these as exact string replacements. A `.trivy-backup` file is kept alongside each modified file until the git commit succeeds.

---

## Security Notes

- The agent never merges to `main` directly — it always opens a PR for human review.
- Backups are created before any file is modified and cleaned up after a successful commit.
- On failure, `patcher.restore_backups()` is called to undo partial changes.
- API keys (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `VCS_TOKEN`) are read from environment variables and never written to disk.

---

## License

MIT

