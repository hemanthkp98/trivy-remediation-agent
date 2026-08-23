# trivy-remediation-agent

Automated vulnerability remediation pipeline that parses Trivy security scans, generates precision code patches using LLMs (Claude or Gemini), and opens remediation Pull Requests.

---

## Why It Exists

Container and dependency security scans frequently uncover dozens of vulnerabilities, but manual remediation through package bumping and Dockerfile editing creates significant engineering toil. `trivy-remediation-agent` automates the remediation lifecycle by reading Trivy JSON reports, analyzing project dependencies against LLM intelligence, and delivering tested code patches directly into reviewable Pull Requests.

---

## Quickstart

```bash
# 1. Install dependencies and configure environment
pip install -r requirements.txt && cp .env.example .env

# 2. Scan your container image
trivy image --format json --output trivy-report.json <IMAGE_NAME>:<TAG>

# 3. Preview fixes with a dry run
python -m src.main --report trivy-report.json --repo . --dry-run

# 4. Apply fixes and open a Pull Request
python -m src.main --report trivy-report.json --repo .
```

---

## Documentation

- [Getting Started](docs/getting-started.md) — Prerequisites, installation options, Trivy scan workflows, and Docker container execution.
- [Configuration](docs/configuration.md) — Configuration file schema, CLI flags, and LLM provider setup (Gemini & Claude).
- [Deployment & CI/CD](docs/deployment.md) — GitHub/GitLab VCS token provisioning, CI/CD pipeline automation, and HTML trend dashboards.
- [Architecture](docs/architecture.md) — Pipeline design, supported vulnerability classes, and structured LLM patch generation.
- [Security Policy](SECURITY.md) — Security model, token scopes, file backup guarantees, and vulnerability reporting.

---

## Architecture

`trivy-remediation-agent` uses a 4-stage pipeline (Parse → Filter → LLM Analysis → Patch & PR) with built-in transactional backups to ensure zero-risk remediation:

```
Trivy JSON Report ──► Parse & Filter (HIGH+) ──► LLM Analyzer (Claude/Gemini) ──► Patcher ──► Git Branch & PR
```

For complete implementation details and JSON schema specifications, see [Architecture](docs/architecture.md).

---

## Contributing & License

- Security policies and token guidelines are detailed in [SECURITY.md](SECURITY.md).
- Distributed under the MIT License.
