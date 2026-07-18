# Dockerfile for the trivy-remediation-agent runner itself.
# Use this image in your CI/CD pipeline to run the remediation stage.
#
# Build:  docker build -t trivy-remediation-agent:latest .
# Run:    docker run --rm \
#           -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
#           -e VCS_TOKEN=$VCS_TOKEN \
#           -v /path/to/repo:/repo \
#           -v /path/to/trivy-report.json:/report.json \
#           trivy-remediation-agent:latest \
#           --report /report.json --repo /repo

FROM python:3.12-slim

# Install git (needed for git operations inside the container)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /agent

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY config/ ./config/

# Configure git to allow operations on mounted repositories
RUN git config --global --add safe.directory /repo

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]
