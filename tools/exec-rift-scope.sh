#!/usr/bin/env bash
# Trusted outer-scope wall/resource supervisor.
# Runs inside the transient cgroup so every descendant remains accounted.
set -euo pipefail

[[ $# -ge 5 ]] || {
  echo "usage: exec-rift-scope.sh <timeout-marker> <status-file> <seconds> <command> ..." >&2
  exit 2
}

marker=$1; shift
status_file=$1; shift
seconds=$1; shift

cgroup_rel=$(awk -F: '$1=="0" {print $3; exit}' /proc/self/cgroup 2>/dev/null || true)
cgroup_root=/sys/fs/cgroup
cgroup_dir="$cgroup_root$cgroup_rel"

read_event() {
  local file=$1 key=$2
  if [[ -r "$file" ]]; then
    awk -v key="$key" '$1==key {print $2; found=1; exit} END {if(!found) print 0}' "$file"
  else
    echo 0
  fi
}

memory_events="$cgroup_dir/memory.events"
pids_events="$cgroup_dir/pids.events"

oom_before=$(read_event "$memory_events" oom_kill)
pids_before=$(read_event "$pids_events" max)

set +e
/usr/bin/timeout --signal=TERM --kill-after=2s "${seconds}s" "$@"
rc=$?
set -e

oom_after=$(read_event "$memory_events" oom_kill)
pids_after=$(read_event "$pids_events" max)

timed_out=0
if [[ $rc -eq 124 || $rc -eq 137 ]]; then
  # rc=137 can also mean a cgroup OOM kill; only stamp the timeout marker when
  # GNU timeout itself reached the deadline. If oom_kill increased, resource
  # classification takes precedence.
  if (( oom_after <= oom_before )); then
    : > "$marker"
    timed_out=1
  fi
fi

cat > "$status_file" <<STATUS
rc=$rc
cgroup=$cgroup_rel
memory_oom_kill_delta=$((oom_after - oom_before))
pids_max_delta=$((pids_after - pids_before))
timed_out=$timed_out
STATUS

exit "$rc"
