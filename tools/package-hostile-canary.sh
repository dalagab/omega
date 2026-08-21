#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-"$root/artifacts/rift-hostile-canary.zip"}
configuration=${2:-Release}
project="$root/tests/fixtures/RiftHostileCanary/RiftHostileCanary.csproj"

python3 "$root/tools/check-hostile-canary-contract.py"
dotnet build "$project" --configuration "$configuration" "$@" >/dev/null

tfm=net10.0
dll="$root/tests/fixtures/RiftHostileCanary/bin/$configuration/$tfm/RiftHostileCanary.dll"
[[ -s "$dll" ]] || { echo "error: canary DLL not found: $dll" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$dll" "$stage/RiftHostileCanary.dll"
mkdir -p "$(dirname "$out")"
rm -f "$out"
(
  cd "$stage"
  zip -q -9 "$out" RiftHostileCanary.dll
)

# Stronger than a malformed manifest: the executable fixture artifact carries NO JSON.
if unzip -Z1 "$out" | grep -Eiq '\.json$'; then
  echo "error: hostile canary artifact must contain zero .json files" >&2
  exit 1
fi
entries=$(unzip -Z1 "$out" | sed '/^$/d')
[[ "$entries" == "RiftHostileCanary.dll" ]] || {
  echo "error: hostile canary artifact must contain only RiftHostileCanary.dll" >&2
  printf '%s\n' "$entries" >&2
  exit 1
}
sha256sum "$out" > "$out.sha256"
echo "$out"
