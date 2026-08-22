#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-"$root/artifacts/rift-alpha.zip"}
[[ $# -gt 0 ]] && shift || true
configuration=${1:-Release}
[[ $# -gt 0 ]] && shift || true
project="$root/tests/fixtures/RiftAlpha/RiftAlpha.csproj"

python3 "$root/tools/check-alpha-contract.py"
dotnet build "$project" --configuration "$configuration" "$@" >/dev/null

tfm=net10.0
dll="$root/tests/fixtures/RiftAlpha/bin/$configuration/$tfm/RiftAlpha.dll"
[[ -s "$dll" ]] || { echo "error: Alpha DLL not found: $dll" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$dll" "$stage/RiftAlpha.dll"
mkdir -p "$(dirname "$out")"
rm -f "$out"
(
  cd "$stage"
  zip -q -9 "$out" RiftAlpha.dll
)

# Stronger than a malformed manifest: the executable fixture artifact carries NO JSON.
if unzip -Z1 "$out" | grep -Eiq '\.json$'; then
  echo "error: Alpha artifact must contain zero .json files" >&2
  exit 1
fi
entries=$(unzip -Z1 "$out" | sed '/^$/d')
[[ "$entries" == "RiftAlpha.dll" ]] || {
  echo "error: Alpha artifact must contain only RiftAlpha.dll" >&2
  printf '%s\n' "$entries" >&2
  exit 1
}
sha256sum "$out" > "$out.sha256"
echo "$out"
