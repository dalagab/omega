#!/usr/bin/env bash
# Fail-closed Bubblewrap capability probe for Interdimensional Rift.
set -euo pipefail

BWRAP=${BWRAP:-$(command -v bwrap || true)}
if [[ -z "$BWRAP" || ! -x "$BWRAP" ]]; then
  echo "error: bubblewrap (bwrap) is not installed" >&2
  exit 2
fi

# Modern Bubblewrap no longer needs or supports the historical setuid mode.
if [[ -u "$BWRAP" ]]; then
  echo "error: refusing setuid Bubblewrap binary: $BWRAP" >&2
  exit 3
fi

if command -v getcap >/dev/null 2>&1; then
  caps=$(getcap "$BWRAP" 2>/dev/null || true)
  if [[ -n "$caps" ]]; then
    echo "error: refusing Bubblewrap binary with file capabilities: $caps" >&2
    exit 3
  fi
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s\n' 'rift-allowed-fixture' > "$work/allowed"
export RIFT_SHOULD_NOT_LEAK='rift-secret-sentinel'

common=(
  --unshare-user
  --unshare-ipc
  --unshare-pid
  --unshare-net
  --unshare-uts
  --unshare-cgroup-try
  --disable-userns
  --new-session
  --die-with-parent
  --cap-drop ALL
  --clearenv
  --hostname rift-probe
  --ro-bind /usr /usr
  --ro-bind /lib /lib
  --ro-bind-try /lib64 /lib64
  --proc /proc
  --dev /dev
  --ro-bind "$work/allowed" /fixture/allowed
  --tmpfs /tmp
  --setenv HOME /tmp
  --setenv PATH /usr/bin:/bin
)

# 1. Basic namespace/mount construction must succeed.
"$BWRAP" "${common[@]}" -- /usr/bin/test -r /fixture/allowed

# 2. The host environment must not leak through --clearenv.
env_dump=$("$BWRAP" "${common[@]}" -- /usr/bin/env)
if grep -q 'RIFT_SHOULD_NOT_LEAK' <<<"$env_dump"; then
  echo "error: host environment leaked into Bubblewrap sandbox" >&2
  exit 4
fi

# 3. Network namespace must not contain a non-loopback/default route.
route_dump=$("$BWRAP" "${common[@]}" -- /usr/bin/cat /proc/net/route 2>/dev/null || true)
if awk 'NR > 1 && $2 == "00000000" { found=1 } END { exit found ? 0 : 1 }' <<<"$route_dump"; then
  echo "error: Bubblewrap network namespace unexpectedly has a default route" >&2
  exit 5
fi

# 4. --disable-userns must prevent the prisoner from creating a nested userns.
if "$BWRAP" "${common[@]}" -- /usr/bin/unshare -Ur /usr/bin/true >/dev/null 2>&1; then
  echo "error: nested user namespace creation succeeded inside the Rift sandbox" >&2
  exit 6
fi

printf 'Bubblewrap boundary OK: %s\n' "$($BWRAP --version)"
