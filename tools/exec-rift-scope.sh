#!/usr/bin/env bash
# Trusted outer-scope wall-time supervisor. Runs inside the transient cgroup so
# every descendant remains resource-accounted even if the plugin forks.
set -euo pipefail
[[ $# -ge 4 ]] || { echo "usage: exec-rift-scope.sh <timeout-marker> <seconds> <command> ..." >&2; exit 2; }
marker=$1; shift
seconds=$1; shift
set +e
/usr/bin/timeout --signal=TERM --kill-after=2s "${seconds}s" "$@"
rc=$?
set -e
if [[ $rc -eq 124 || $rc -eq 137 ]]; then
  : > "$marker"
fi
exit "$rc"
