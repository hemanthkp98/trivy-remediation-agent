# Deployment & CI/CD Integration

Set up VCS tokens, configure CI/CD pipeline automation, and generate historical trend reporting dashboards.

---

## VCS Token Setup

The `VCS_TOKEN` environment variable provides authentication required to push remediation branches, open Pull/Merge Requests, and maintain history records.

### GitHub PAT Provisioning

Create a **Fine-grained Personal Access Token (PAT)** for least-privilege security:

1. Navigate to **Settings** → **Developer settings** → **Personal access tokens** → **Fine-grained tokens**.
2. Click **Generate new token**.
3. Under **Repository access**, select *Only select repositories* and choose your target application repository.
4. Under **Repository permissions**, grant the following:
   - **Contents**: `Read and write` (to create remediation branches and store history logs)
   - **Pull requests**: `Read and write` (to open remediation PRs)
5. Copy the generated token and export it as `VCS_TOKEN`.

> [!NOTE]
> If using GitHub Classic PATs, select the `repo` scope.

### GitLab Token Provisioning

1. Navigate to **User Settings** → **Access Tokens** (or Project Access Tokens).
2. Name the token `trivy-remediation-agent`.
3. Select scopes: **`api`** and **`write_repository`**.
4. Copy the token and export it as `VCS_TOKEN`.

---

## CI/CD Secret Configuration

Store your credentials in your CI/CD platform:

- **GitHub Actions**: Add as a repository secret under **Settings** → **Secrets and variables** → **Actions** named `VCS_TOKEN`, `GEMINI_API_KEY`, or `ANTHROPIC_API_KEY`.
- **GitLab CI**: Add as masked CI/CD variables under **Settings** → **CI/CD** → **Variables**.

---

## History & Trend Dashboard Reporting

`trivy-remediation-agent` maintains an automated run history on a dedicated orphan branch (`trivy-bot/history`) via direct VCS REST API calls, avoiding ephemeral runner data loss during CI/CD runs.

### Generating HTML Trend Dashboards

Generate interactive, self-contained HTML dashboards visualizing CVE trends, recurring regressions, MTTR (Mean Time To Remediate), and execution logs:

```bash
# Generate dashboard from recorded history
python -m src.main scan-report --output report.html --open

# Limit to the last 10 runs and push the dashboard back to the history branch
python -m src.main scan-report --last 10 --push
```

### Standalone Single-Run Summary

To produce a self-contained HTML report artifact for a single remediation run (useful for CI artifact upload steps):

```bash
python -m src.main remediate --report trivy-report.json --repo . --output summary.html
```
