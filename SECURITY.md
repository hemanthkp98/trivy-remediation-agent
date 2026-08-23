# Security Policy

Security guidelines, access token permission requirements, and vulnerability reporting process for trivy-remediation-agent.

---

## Security Model & Principles

- **Human-in-the-Loop PR Gate**: The agent never commits or pushes directly to default branches (such as `main` or `master`). All remediation changes are submitted as Pull/Merge Requests on a new branch for human review and CI verification before merging.
- **Transactional File Backups**: Before modifying any source file on disk, `patcher` creates an in-place `.trivy-backup` copy. If any error occurs during processing, `patcher.restore_backups()` is triggered automatically to roll back changes.
- **Environment-based Secret Handling**: All API keys (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`) and VCS tokens (`VCS_TOKEN`) are loaded from environment variables into memory and are never written to disk or logged.
- **Isolated Execution**: When running in CI/CD, use fine-grained access tokens scoped strictly to target repositories.

---

## Token Scope Recommendations

| Platform | Recommended Token Type | Required Scopes |
|---|---|---|
| **GitHub** | Fine-grained PAT | **Contents**: `Read and write`<br>**Pull requests**: `Read and write` |
| **GitLab** | Project Access Token | **Scopes**: `api`, `write_repository` |

---

## Reporting Vulnerabilities

If you discover a security vulnerability within `trivy-remediation-agent`, please report it responsibly by contacting the project maintainer or opening a private security advisory.
