#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
name=${1:-}
out=${2:-}
configuration=${3:-Release}
shift $(( $# >= 3 ? 3 : $# )) || true

case "$name" in
  RiftMemoryPressure|RiftTaskPressure|RiftTmpfsPressure|RiftHangTree) ;;
  *) echo "error: unsupported fixture: $name" >&2; exit 2 ;;
esac

[[ -n "$out" ]] || out="$root/artifacts/${name}.zip"
python3 "$root/tools/check-sandbox-fixtures.py"

project="$root/tests/fixtures/$name/$name.csproj"
dotnet build "$project" --configuration "$configuration" "$@" >/dev/null

dll="$root/tests/fixtures/$name/bin/$configuration/net10.0/$name.dll"
[[ -s "$dll" ]] || { echo "error: fixture DLL not found: $dll" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$dll" "$stage/$name.dll"

if [[ "$name" == RiftHangTree ]]; then
  gcc -O2 -Wall -Wextra \
    "$root/tests/fixtures/RiftHangTree/rift-hang-child.c" \
    -o "$stage/rift-hang-child"
  chmod 0755 "$stage/rift-hang-child"
fi

mkdir -p "$(dirname "$out")"
rm -f "$out"
(
  cd "$stage"
  if [[ "$name" == RiftHangTree ]]; then
    zip -q -9 "$out" "$name.dll" rift-hang-child
  else
    zip -q -9 "$out" "$name.dll"
  fi
)

if unzip -Z1 "$out" | grep -Eiq '\.json$'; then
  echo "error: containment fixture artifact must contain zero JSON files" >&2
  exit 1
fi

sha256sum "$out" > "$out.sha256"
echo "$out"
