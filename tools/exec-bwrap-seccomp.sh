#!/usr/bin/env bash
# Open the precompiled BPF policy inside the cgroup-scoped launcher and pass the
# inherited fd to bwrap. Keeping this wrapper inside the scope avoids relying on
# systemd-run preserving caller-created file descriptors.
set -euo pipefail
[[ $# -ge 3 ]] || { echo "usage: exec-bwrap-seccomp.sh <policy.bpf> <bwrap> <bwrap args...>" >&2; exit 2; }
policy=$1; shift
bwrap=$1; shift
[[ -r "$policy" && -s "$policy" ]] || { echo "error: invalid seccomp policy: $policy" >&2; exit 2; }
exec 9<"$policy"
exec "$bwrap" --seccomp 9 "$@"
