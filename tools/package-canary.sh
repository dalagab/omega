#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-"$root/artifacts/rift-canary.zip"}
[[ $# -gt 0 ]] && shift || true
configuration=${1:-Release}
[[ $# -gt 0 ]] && shift || true
project="$root/tests/fixtures/RiftCanary/RiftCanary.csproj"

python3 "$root/tools/check-canary-contract.py"
dotnet build "$project" --configuration "$configuration" "$@" >/dev/null

dll="$root/tests/fixtures/RiftCanary/bin/$configuration/net10.0/RiftCanary.dll"
[[ -s "$dll" ]] || { echo "error: Canary DLL not found: $dll" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$dll" "$stage/RiftCanary.dll"
mkdir -p "$(dirname "$out")"
rm -f "$out"
(cd "$stage" && zip -q -9 "$out" RiftCanary.dll)
entries=$(unzip -Z1 "$out" | sed '/^$/d')
[[ "$entries" == "RiftCanary.dll" ]] || { echo "error: Canary must be DLL-only" >&2; exit 1; }
if unzip -Z1 "$out" | grep -Eiq '\.json$'; then
  echo "error: Canary artifact must contain zero JSON files" >&2
  exit 1
fi
sha256sum "$out" > "$out.sha256"
echo "$out"
