ARG PYTHON_IMAGE=python:3.13.15-slim-bookworm
FROM ${PYTHON_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends binutils ca-certificates clamav clamav-freshclam curl file gh git jq unzip yara \
 && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir PyYAML==6.0.3
LABEL org.opencontainers.image.title="Omega SigmaScope worker toolchain" \
      org.opencontainers.image.description="Toolchain-only Linux SigmaScope image with YARA/ClamAV executables; frozen rules/databases/Definitions are supplied and verified at runtime."
WORKDIR /workspace
