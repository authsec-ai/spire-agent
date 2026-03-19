# Multi-stage build for SPIRE Agent
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install the package with all dependencies
COPY setup.py pyproject.toml ./
COPY icp_agent/ ./icp_agent/
RUN pip install --no-cache-dir .

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy application code and config
COPY icp_agent/ ./icp_agent/
COPY setup.py pyproject.toml ./
COPY config.yaml .

# Create required directories and non-root user
RUN mkdir -p /var/lib/spire-agent/cache /var/run/spire-agent && \
    chmod 700 /var/lib/spire-agent/cache && \
    useradd -m -u 1000 spire-agent && \
    chown -R spire-agent:spire-agent /var/lib/spire-agent /var/run/spire-agent /app

USER spire-agent

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

ENTRYPOINT ["python", "-m", "icp_agent"]
CMD ["-c", "/app/config.yaml"]
