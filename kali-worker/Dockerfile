# =============================================================================
# Stage 1 — Go Builder
# =============================================================================
FROM golang:1.23-bullseye AS go-builder

WORKDIR /build

COPY server-go/go.mod server-go/go.sum ./
RUN go mod download

COPY server-go/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /kali-agent-server ./cmd/main.go


# =============================================================================
# Stage 2 — Ubuntu 22.04 runtime
# =============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# ── 1. Base packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libffi-dev \
    libssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── 2. Pentest tools ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    whois \
    sqlmap \
    nikto \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── 3. ffuf — pre-built binary ────────────────────────────────────────────────
RUN curl -fsSL \
    https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf

# ── 4. MCP SDK only — official Anthropic package ──────────────────────────────
RUN python3 -m venv /opt/mcp-venv \
    && /opt/mcp-venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/mcp-venv/bin/pip install 'mcp>=1.0.0,<2.0.0' 'httpx>=0.25.0' 'starlette>=0.30.0' 'uvicorn>=0.24.0' 'pydantic>=2.0.0'

ENV PATH="/opt/mcp-venv/bin:$PATH"

# ── 5. Copy our MCP server script ─────────────────────────────────────────────
COPY kali-worker/mcp_server.py /opt/mcp_server.py

# ── 6. Go binary from Stage 1 ─────────────────────────────────────────────────
COPY --from=go-builder /kali-agent-server /usr/local/bin/kali-agent-server
RUN chmod +x /usr/local/bin/kali-agent-server

# ── 7. Non-root user ──────────────────────────────────────────────────────────
RUN groupadd -r kaliagent \
    && useradd -r -g kaliagent -m -s /bin/bash kaliagent \
    && chown kaliagent:kaliagent /usr/local/bin/kali-agent-server \
    && chown kaliagent:kaliagent /opt/mcp_server.py

# ── 8. Startup script ─────────────────────────────────────────────────────────
COPY kali-worker/start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 5000 8080

USER kaliagent

ENTRYPOINT ["/start.sh"]