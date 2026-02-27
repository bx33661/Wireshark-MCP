FROM python:3.12-slim

LABEL maintainer="bx33661"
LABEL description="Wireshark MCP Server — AI-powered packet analysis"

# Install tshark and clean up
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash mcp \
    && usermod -aG wireshark mcp

WORKDIR /app

# Copy and install package
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Default pcap directory
RUN mkdir -p /data && chown mcp:mcp /data
VOLUME ["/data"]

USER mcp

# Default: SSE transport on port 8080, restrict to /data directory
ENV WIRESHARK_MCP_ALLOWED_DIRS=/data

EXPOSE 8080

ENTRYPOINT ["wireshark-mcp"]
CMD ["--transport", "sse", "--port", "8080", "--log-level", "INFO"]
