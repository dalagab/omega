#!/usr/bin/env sh
set -eu
DESKTOP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$DESKTOP")
LAUNCHER_VERSION=$(tr -d '\r\n ' < "$DESKTOP/launcher-version.txt")
if ! printf '%s\n' "$LAUNCHER_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Invalid DeltaScope launcher version: $LAUNCHER_VERSION" >&2
  exit 2
fi
mkdir -p "$ROOT/dist"
cd "$DESKTOP"
go test ./...
go build -trimpath -ldflags "-s -w -X main.launcherVersion=$LAUNCHER_VERSION -X main.buildFlavor=console" -o "$ROOT/dist/deltascope-desktop" ./cmd/deltascope-desktop
echo "Built $ROOT/dist/deltascope-desktop (launcher $LAUNCHER_VERSION)"
