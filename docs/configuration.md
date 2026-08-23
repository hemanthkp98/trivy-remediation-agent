# Configuration

Configure LLM backends, severity filters, VCS authentication, and CLI options for trivy-remediation-agent.

---

## Configuration File

The default configuration file lives in `config/config.yaml`. Copy and edit this file to suit your project:

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

### Configuration Options Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `min_severity` | `string` | `HIGH` | Minimum vulnerability severity threshold to remediate (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `llm.provider` | `string` | `gemini` | LLM backend to use for analysis (`gemini` or `claude`). |
| `llm.model` | `string` | `gemini-2.5-pro` | Model identifier to request from the LLM provider. |
| `llm.max_tokens` | `integer` | `8192` | Maximum token limit for LLM generation response. |
| `vcs.provider` | `string` | `github` | Version control system (`github` or `gitlab`). |
| `vcs.token_env` | `string` | `VCS_TOKEN` | Name of the environment variable containing the VCS access token. |
| `vcs.repo` | `string` | — | Repository target (`owner/repo` for GitHub, project path/ID for GitLab). |
| `vcs.base_branch` | `string` | `main` | Base branch to branch from and target with remediation Pull Requests. |
| `vcs.pr_title` | `string` | `fix: auto-remediate {count} Trivy vulnerabilities` | Title template for generated Pull Requests. |

---

## CLI Options Reference

All configuration values can be overridden dynamically using command-line arguments:

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--report` | `-r` | `PATH` | *Required* | Path to the Trivy JSON report file (`trivy-report.json`). |
| `--repo` | `-R` | `PATH` | `.` | Path to the root of the target source repository. |
| `--config` | `-c` | `PATH` | `config/config.yaml` | Path to custom YAML configuration file. |
| `--severity` | `-s` | `LEVEL` | `HIGH` | Minimum severity filter (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `--provider` | `-p` | `NAME` | `gemini` | LLM backend provider (`gemini` or `claude`). |
| `--dry-run` | `-n` | `flag` | `false` | Run analysis and patch preview without performing Git commits or opening PRs. |
| `--help` | | `flag` | | Display help message and exit. |

---

## LLM Providers

The agent supports two LLM backends, switchable via configuration, CLI flag, or environment variables.

| Provider | CLI Flag | Config Value | API Key Environment Variable | Default Model |
|---|---|---|---|---|
| **Google Gemini** | `--provider gemini` | `llm.provider: gemini` | `GEMINI_API_KEY` | `gemini-2.5-pro` |
| **Anthropic Claude** | `--provider claude` | `llm.provider: claude` | `ANTHROPIC_API_KEY` | `claude-opus-4-6` |

### Acquiring API Keys

- **Gemini**: Obtain a key via [Google AI Studio](https://aistudio.google.com/apikey) (free tier available).
- **Claude**: Obtain a key via the [Anthropic Console](https://console.anthropic.com/).

### Switching Providers

#### 1. Via CLI Flag
```bash
python -m src.main --report trivy-report.json --repo . --provider gemini --dry-run
python -m src.main --report trivy-report.json --repo . --provider claude --dry-run
```

#### 2. Via `config/config.yaml`
```yaml
llm:
  provider: claude
  model: claude-opus-4-6
```

#### 3. Via Environment Variables
```bash
# Gemini
export GEMINI_API_KEY="<YOUR_GEMINI_API_KEY>"

# Claude
export ANTHROPIC_API_KEY="<YOUR_ANTHROPIC_API_KEY>"
```
