#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out=${1:-"$root/artifacts/rift-alpha-seccomp-$(uname -m).bpf"}
mkdir -p "$(dirname "$out")"
command -v cc >/dev/null 2>&1 || { echo "error: C compiler required" >&2; exit 2; }
command -v pkg-config >/dev/null 2>&1 || { echo "error: pkg-config required" >&2; exit 2; }
pkg-config --exists libseccomp || { echo "error: libseccomp development package required" >&2; exit 2; }
bin=$(mktemp)
trap 'rm -f "$bin"' EXIT
cc -O2 -Wall -Wextra -Werror \
  $(pkg-config --cflags libseccomp) \
  "$root/shared/rift-boundary/seccomp/rift-alpha-seccomp-export.c" \
  -o "$bin" $(pkg-config --libs libseccomp)
"$bin" "$out"
[[ -s "$out" ]] || { echo "error: empty seccomp policy" >&2; exit 1; }
echo "$out"
