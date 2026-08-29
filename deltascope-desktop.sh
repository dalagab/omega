#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x "$ROOT/dist/deltascope-desktop" ]; then
  exec "$ROOT/dist/deltascope-desktop" "$@"
fi
if ! command -v go >/dev/null 2>&1; then
  echo "DeltaScope Desktop binary is not built and Go is not available." >&2
  echo "Run desktop/build.sh on a development machine or use deltascope.sh." >&2
  exit 2
fi
cd "$ROOT/desktop"
exec go run ./cmd/deltascope-desktop "$@"
