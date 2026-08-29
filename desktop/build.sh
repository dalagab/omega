#!/usr/bin/env sh
set -eu
DESKTOP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$DESKTOP")
mkdir -p "$ROOT/dist"
cd "$DESKTOP"
go test ./...
go build -trimpath -ldflags "-s -w -X main.version=4.21.12 -X main.buildFlavor=console" -o "$ROOT/dist/deltascope-desktop" ./cmd/deltascope-desktop
echo "Built $ROOT/dist/deltascope-desktop"
