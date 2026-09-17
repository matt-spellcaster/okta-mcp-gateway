# Okta's okta-mcp-server packaged for the Docker MCP Gateway.
# Base image pinned by digest; dependencies pinned by version and hash.
# To upgrade: bump image/requirements.in, re-run scripts/lock.sh, rebuild.
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHON_KEYRING_BACKEND=memkeyring.MemoryKeyring \
    PYTHONPATH=/opt/mcp

COPY requirements.txt /tmp/requirements.txt
RUN pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

COPY memkeyring.py /opt/mcp/memkeyring.py

# Unprivileged user with no home-directory secrets.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp
USER 10001:10001

LABEL org.opencontainers.image.title="okta-mcp-gateway" \
      org.opencontainers.image.description="okta-mcp-server 1.1.6 for Docker MCP Gateway"

ENTRYPOINT ["okta-mcp-server"]
