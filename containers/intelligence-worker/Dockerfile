ARG PYTHON_IMAGE=python:3.13.15-slim-bookworm
FROM ${PYTHON_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl dnsutils gh git jq openssl \
 && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir PyYAML==6.0.3
LABEL org.opencontainers.image.title="Omega intelligence worker toolchain" \
      org.opencontainers.image.description="Toolchain-only image for TTL-backed Threat Intelligence, DNS and advisory collectors; feeds are supplied at runtime."
WORKDIR /workspace
