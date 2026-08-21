#!/usr/bin/env bash
set -euo pipefail
command -v systemd-run >/dev/null 2>&1 || { echo "error: systemd-run is required" >&2; exit 1; }
command -v sudo >/dev/null 2>&1 || { echo "error: sudo is required on the GitHub runner" >&2; exit 1; }
unit="rift-cgroup-probe-${GITHUB_RUN_ID:-local}-$$"
cleanup() { sudo systemctl stop "$unit.service" >/dev/null 2>&1 || true; }
trap cleanup EXIT
sudo systemd-run \
  --quiet --wait --pipe --collect --service-type=exec \
  --unit "$unit" \
  --uid "$(id -u)" --gid "$(id -g)" \
  --property=MemoryMax=64M \
  --property=MemorySwapMax=0 \
  --property=TasksMax=16 \
  --property=CPUQuota=100% \
  --property=RuntimeMaxSec=10s \
  --property=KillMode=control-group \
  --property=SendSIGKILL=yes \
  /usr/bin/true
trap - EXIT
printf 'Rift cgroup-v2 resource boundary: ok\n'
