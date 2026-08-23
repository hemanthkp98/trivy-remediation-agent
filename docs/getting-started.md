# Getting Started

Get up and running with trivy-remediation-agent to automatically fix container and dependency vulnerabilities from Trivy scans.

---

## Prerequisites

Before running the remediation agent, ensure you have:

- **Python**: Version 3.11+
- **LLM API Key**: Google Gemini API key (`GEMINI_API_KEY`) or Anthropic Claude API key (`ANTHROPIC_API_KEY`) (see [Configuration](configuration.md#llm-providers))
- **VCS Token**: GitHub Personal Access Token or GitLab Token with write access for branch creation and pull requests (see [Deployment & VCS Setup](deployment.md#vcs-token-setup))

---

## Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/hemanthkp98/trivy-remediation-agent
cd trivy-remediation-agent
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` to provide your API keys:

```bash
# Add your LLM API key and VCS token
GEMINI_API_KEY="<YOUR_GEMINI_API_KEY>"
VCS_TOKEN="<YOUR_GITHUB_OR_GITLAB_TOKEN>"
```

---

## Running Against a Trivy Report

Follow these steps to scan your container image and generate automated fixes:

### 1. Scan your image with Trivy

```bash
trivy image --format json --output trivy-report.json <IMAGE_NAME>:<TAG>
```

### 2. Preview remediation with a dry run

Run the agent with `--dry-run` to inspect proposed patches without performing any Git commits or creating branches:

```bash
python -m src.main \
  --report trivy-report.json \
  --repo /path/to/your/app \
  --dry-run
```

### 3. Run remediation for real

When satisfied with the dry-run output, execute the agent to create the branch and open a Pull Request:

```bash
python -m src.main \
  --report trivy-report.json \
  --repo /path/to/your/app
```

---

## Running with Docker

You can run the agent inside a Docker container without installing local Python dependencies:

### Build the Docker image

```bash
docker build -t trivy-remediation-agent .
```

### Run with Google Gemini (Default)

```bash
docker run --rm \
  -e GEMINI_API_KEY=$GEMINI_API_KEY \
  -e VCS_TOKEN=$VCS_TOKEN \
  -v $(pwd):/repo \
  -v $(pwd)/trivy-report.json:/report.json \
  trivy-remediation-agent \
  --report /report.json --repo /repo
```

### Run with Anthropic Claude

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e VCS_TOKEN=$VCS_TOKEN \
  -v $(pwd):/repo \
  -v $(pwd)/trivy-report.json:/report.json \
  trivy-remediation-agent \
  --report /report.json --repo /repo --provider claude
```
