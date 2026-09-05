FROM python:3.12-slim-bookworm

ARG WIRESHARK_MCP_VERSION=3.0.0

LABEL org.opencontainers.image.title="Wireshark MCP" \
      org.opencontainers.image.description="MCP server for trustworthy Wireshark and tshark packet analysis" \
      org.opencontainers.image.source="https://github.com/bx33661/Wireshark-MCP" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends ca-certificates tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade "setuptools>=83" \
    && python -m pip install --no-cache-dir "wireshark-mcp==${WIRESHARK_MCP_VERSION}" \
    && groupadd --gid 10001 wireshark-mcp \
    && useradd --uid 10001 --gid 10001 --create-home wireshark-mcp \
    && mkdir --parents /captures /results \
    && chown wireshark-mcp:wireshark-mcp /captures /results

USER wireshark-mcp
WORKDIR /captures

EXPOSE 8080

ENTRYPOINT ["wireshark-mcp"]
CMD ["serve", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8080", "--allow-insecure-http", "--profile", "analysis"]
