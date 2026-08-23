#!/usr/bin/env bash
# Execute one plugin artifact in a cgroup-v2 + Bubblewrap + seccomp boundary.
# Production behavior is fail-closed: missing cgroup/systemd, bwrap, or seccomp
# policy is an error, never a reason to run the plugin directly.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  run-rift-bwrap.sh \
    --runtime-dir <self-contained-rift-publish-dir> \
    --contract-dir <frozen-trusted-dalamud-runtime-dir> \
    [--contract-track unknown] \
    --plugin <entry-plugin.dll> \
    --artifact-dir <exact-staged-artifact-dir> \
    --seccomp-policy <rift-policy.bpf> \
    --out <report.json> \
    [--init-timeout 10] \
    [--exercise-profile post-init-safe-v1] \
    [--framework-ticks 3] \
    [--wall-timeout 20] \
    [--memory-max 768M] \
    [--tasks-max 64] \
    [--cpu-quota 100%]
USAGE
}

runtime_dir=''
contract_dir=''
plugin=''
artifact_dir=''
seccomp_policy=''
out=''
init_timeout=10
wall_timeout=20
memory_max=768M
tasks_max=64
cpu_quota=100%
tmpfs_tmp_bytes=134217728
tmpfs_home_bytes=16777216
tmpfs_work_bytes=67108864
boundary_profile=rift-linux-bwrap-v3
contract_mode=real-dalamud-contract-failfast
contract_track=unknown
exercise_profile=post-init-safe-v1
framework_ticks=3

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-dir) runtime_dir=${2:-}; shift 2 ;;
    --contract-dir) contract_dir=${2:-}; shift 2 ;;
    --contract-track) contract_track=${2:-}; shift 2 ;;
    --plugin) plugin=${2:-}; shift 2 ;;
    --artifact-dir) artifact_dir=${2:-}; shift 2 ;;
    --seccomp-policy) seccomp_policy=${2:-}; shift 2 ;;
    --out) out=${2:-}; shift 2 ;;
    --init-timeout) init_timeout=${2:-}; shift 2 ;;
    --exercise-profile) exercise_profile=${2:-}; shift 2 ;;
    --framework-ticks) framework_ticks=${2:-}; shift 2 ;;
    --wall-timeout) wall_timeout=${2:-}; shift 2 ;;
    --memory-max) memory_max=${2:-}; shift 2 ;;
    --tasks-max) tasks_max=${2:-}; shift 2 ;;
    --cpu-quota) cpu_quota=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$runtime_dir" && -d "$runtime_dir" ]] || { echo "error: --runtime-dir is required" >&2; exit 2; }
[[ -n "$contract_dir" && -d "$contract_dir" && -s "$contract_dir/Dalamud.dll" ]] || { echo "error: --contract-dir with Dalamud.dll is required" >&2; exit 2; }
[[ -n "$plugin" && -f "$plugin" ]] || { echo "error: --plugin is required" >&2; exit 2; }
[[ -n "$artifact_dir" && -d "$artifact_dir" ]] || { echo "error: --artifact-dir is required" >&2; exit 2; }
[[ -n "$seccomp_policy" && -s "$seccomp_policy" ]] || { echo "error: --seccomp-policy is required" >&2; exit 2; }
[[ -n "$out" ]] || { echo "error: --out is required" >&2; exit 2; }
[[ "$init_timeout" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "error: invalid --init-timeout" >&2; exit 2; }
[[ "$exercise_profile" == "post-init-safe-v1" || "$exercise_profile" == "none" ]] || { echo "error: invalid --exercise-profile" >&2; exit 2; }
[[ "$framework_ticks" =~ ^[0-9]+$ && "$framework_ticks" -le 32 ]] || { echo "error: invalid --framework-ticks" >&2; exit 2; }
[[ "$wall_timeout" =~ ^[0-9]+$ && "$wall_timeout" -gt 0 ]] || { echo "error: invalid --wall-timeout" >&2; exit 2; }
[[ "$memory_max" =~ ^[0-9]+([KMGTP])?$ ]] || { echo "error: invalid --memory-max" >&2; exit 2; }
[[ "$tasks_max" =~ ^[0-9]+$ && "$tasks_max" -gt 0 ]] || { echo "error: invalid --tasks-max" >&2; exit 2; }
[[ "$cpu_quota" =~ ^[0-9]+%$ ]] || { echo "error: invalid --cpu-quota" >&2; exit 2; }

for command in bwrap systemd-run systemctl sudo timeout sha256sum realpath; do
  command -v "$command" >/dev/null 2>&1 || { echo "error: $command is required" >&2; exit 2; }
done

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
launcher="$root/tools/exec-bwrap-seccomp.sh"
scope_runner="$root/tools/exec-rift-scope.sh"
[[ -f "$launcher" && -f "$scope_runner" ]] || { echo "error: Rift supervisor helpers missing" >&2; exit 2; }

runtime_dir=$(realpath "$runtime_dir")
contract_dir=$(realpath "$contract_dir")
plugin=$(realpath "$plugin")
artifact_dir=$(realpath "$artifact_dir")
seccomp_policy=$(realpath "$seccomp_policy")
out=$(realpath -m "$out")
mkdir -p "$(dirname "$out")"

[[ "$contract_track" == "release" || "$contract_track" == "stg" || "$contract_track" == "unknown" ]] || {
  echo "error: --contract-track must be release, stg, or unknown" >&2
  exit 2
}
contract_dalamud_sha=$(sha256sum "$contract_dir/Dalamud.dll" | awk '{print $1}')
contract_tree_sha=$(python3 "$root/tools/hash-artifact-tree.py" "$contract_dir")
contract_hash_algorithm='sha256(path-nul-file-sha-lf-v1)'

case "$plugin" in
  "$artifact_dir"/*) ;;
  *) echo "error: plugin entry must be contained by --artifact-dir" >&2; exit 2 ;;
esac
plugin_rel=${plugin#"$artifact_dir"/}
[[ -n "$plugin_rel" && "$plugin_rel" != *'..'* ]] || { echo "error: unsafe plugin path" >&2; exit 2; }

host_bin=''
for candidate in interdimensional-rift sigmascope-sandbox; do
  if [[ -x "$runtime_dir/$candidate" ]]; then
    host_bin="/rift/$candidate"
    break
  fi
done
[[ -n "$host_bin" ]] || { echo "error: runtime directory has no executable self-contained Rift host" >&2; exit 2; }

plugin_sha=$(sha256sum "$plugin" | awk '{print $1}')
# A stable digest of every regular file in the exact staged artifact tree.
artifact_sha=$(python3 "$root/tools/hash-artifact-tree.py" "$artifact_dir")
artifact_hash_algorithm='sha256(path-nul-file-sha-lf-v1)'

tmp_report=$(mktemp)
tmp_stderr=$(mktemp)
timeout_marker=$(mktemp)
scope_status=$(mktemp)
rm -f "$timeout_marker" "$scope_status"
unit="rift-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
cleanup() {
  sudo systemctl stop "$unit.service" >/dev/null 2>&1 || true
  sudo systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  rm -f "$tmp_report" "$tmp_stderr" "$timeout_marker" "$scope_status"
}
trap cleanup EXIT

bwrap_args=(
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
  --hostname interdimensional-rift
  --ro-bind "$runtime_dir" /rift
  --ro-bind "$contract_dir" /contracts
  --ro-bind "$artifact_dir" /input
  --ro-bind /lib /lib
  --ro-bind-try /lib64 /lib64
  --ro-bind /usr/lib /usr/lib
  --proc /proc
  --dev /dev
  --size "$tmpfs_tmp_bytes" --tmpfs /tmp
  --size "$tmpfs_home_bytes" --tmpfs /home
  --size "$tmpfs_work_bytes" --tmpfs /work
  --setenv HOME /home/rift
  --setenv TMPDIR /tmp
  --setenv PATH /rift
  --setenv DOTNET_CLI_TELEMETRY_OPTOUT 1
  --setenv DOTNET_NOLOGO 1
  --setenv DOTNET_BUNDLE_EXTRACT_BASE_DIR /tmp/dotnet-bundle
  --setenv RIFT_EXECUTOR bubblewrap-v2
  --setenv RIFT_DALAMUD_CONTRACT_DIR /contracts
  --setenv RIFT_DALAMUD_CONTRACT_TRACK "$contract_track"
  --setenv RIFT_DALAMUD_CONTRACT_SHA256 "$contract_dalamud_sha"
  --setenv RIFT_DALAMUD_CONTRACT_TREE_SHA256 "$contract_tree_sha"
  --setenv RIFT_DALAMUD_CONTRACT_HASH_ALGORITHM "$contract_hash_algorithm"
  --setenv RIFT_ARTIFACT_TREE_SHA256 "$artifact_sha"
  --setenv RIFT_ARTIFACT_TREE_HASH_ALGORITHM "$artifact_hash_algorithm"
  --setenv RIFT_ENTRY_SHA256 "$plugin_sha"
  --setenv RIFT_NETWORK_MODE isolated
  --setenv RIFT_SECCOMP_MODE enforced
  --setenv RIFT_MEMORY_MAX "$memory_max"
  --setenv RIFT_TASKS_MAX "$tasks_max"
  --setenv RIFT_CPU_QUOTA "$cpu_quota"
  --setenv RIFT_MEMORY_SWAP_MAX "0"
  --setenv RIFT_WALL_TIMEOUT_SECONDS "$wall_timeout"
  --setenv RIFT_TMPFS_TMP_BYTES "$tmpfs_tmp_bytes"
  --setenv RIFT_TMPFS_HOME_BYTES "$tmpfs_home_bytes"
  --setenv RIFT_TMPFS_WORK_BYTES "$tmpfs_work_bytes"
  --setenv RIFT_BOUNDARY_PROFILE "$boundary_profile"
  --setenv RIFT_CONTRACT_MODE "$contract_mode"
  --setenv RIFT_EXERCISE_PROFILE "$exercise_profile"
  --setenv RIFT_FRAMEWORK_TICKS "$framework_ticks"
  --chdir /work
)

set +e
sudo systemd-run \
  --quiet --wait --pipe --service-type=exec \
  --unit "$unit" \
  --uid "$(id -u)" --gid "$(id -g)" \
  --property="MemoryMax=$memory_max" \
  --property=MemorySwapMax=0 \
  --property="TasksMax=$tasks_max" \
  --property="CPUQuota=$cpu_quota" \
  --property="RuntimeMaxSec=$((wall_timeout + 5))s" \
  --property=TimeoutStopSec=2s \
  --property=KillMode=control-group \
  --property=SendSIGKILL=yes \
  --property=NoNewPrivileges=yes \
  --property=OOMPolicy=kill \
  /bin/bash "$scope_runner" "$timeout_marker" "$scope_status" "$wall_timeout" \
  /bin/bash "$launcher" "$seccomp_policy" "$(command -v bwrap)" "${bwrap_args[@]}" -- \
  "$host_bin" "/input/$plugin_rel" --timeout "$init_timeout" --exercise-profile "$exercise_profile" --framework-ticks "$framework_ticks" --no-color \
  >"$tmp_report" 2>"$tmp_stderr"
rc=$?
set -e

# exec-rift-scope.sh is intentionally inside the hostile resource cgroup. If
# memory.max kills that witness too, systemd remains outside the cgroup and is
# therefore the authoritative fallback for OOM classification.
systemd_result=$(sudo systemctl show "$unit.service" --property=Result --value 2>/dev/null || true)
systemd_control_group=$(sudo systemctl show "$unit.service" --property=ControlGroup --value 2>/dev/null || true)
systemd_exec_main_code=$(sudo systemctl show "$unit.service" --property=ExecMainCode --value 2>/dev/null || true)
systemd_exec_main_status=$(sudo systemctl show "$unit.service" --property=ExecMainStatus --value 2>/dev/null || true)

cat "$tmp_stderr" >&2 || true

scope_oom_kill_delta=0
scope_pids_max_delta=0
scope_cgroup=''
if [[ -s "$scope_status" ]]; then
  scope_oom_kill_delta=$(awk -F= '$1=="memory_oom_kill_delta" {print $2}' "$scope_status")
  scope_pids_max_delta=$(awk -F= '$1=="pids_max_delta" {print $2}' "$scope_status")
  scope_cgroup=$(awk -F= '$1=="cgroup" {sub(/^cgroup=/, ""); print}' "$scope_status")
fi
[[ "$scope_oom_kill_delta" =~ ^[0-9]+$ ]] || scope_oom_kill_delta=0
[[ "$scope_pids_max_delta" =~ ^[0-9]+$ ]] || scope_pids_max_delta=0
if [[ -z "$scope_cgroup" && -n "$systemd_control_group" ]]; then
  scope_cgroup="$systemd_control_group"
fi

if [[ -e "$timeout_marker" ]]; then
  cat > "$out" <<JSON
{
  "schema_version": "rift.supervisor.v3",
  "producer": "interdimensional-rift-supervisor",
  "artifact_sha256": "$artifact_sha",
  "artifact_hash_algorithm": "$artifact_hash_algorithm",
  "entry_sha256": "$plugin_sha",
  "execution": {
    "outcome": "wall_timeout",
    "exit_code": $rc,
    "signal": null,
    "wall_timeout_seconds": $wall_timeout,
    "exercise_profile": "$exercise_profile",
    "framework_ticks": $framework_ticks,
    "network": "isolated",
    "seccomp": "enforced",
    "systemd_result": "$systemd_result",
    "systemd_exec_main_code": "$systemd_exec_main_code",
    "systemd_exec_main_status": "$systemd_exec_main_status",
    "boundary_profile": "$boundary_profile",
    "contract_mode": "$contract_mode",
    "dalamud_contract": {
      "track": "$contract_track",
      "dalamud_sha256": "$contract_dalamud_sha",
      "tree_sha256": "$contract_tree_sha",
      "hash_algorithm": "$contract_hash_algorithm"
    },
    "tmpfs": {"tmp_bytes": $tmpfs_tmp_bytes, "home_bytes": $tmpfs_home_bytes, "work_bytes": $tmpfs_work_bytes},
    "cgroup": {
      "path": "$scope_cgroup",
      "memory_max": "$memory_max",
      "memory_swap_max": "0",
      "tasks_max": $tasks_max,
      "cpu_quota": "$cpu_quota",
      "memory_oom_kill_delta": $scope_oom_kill_delta,
      "pids_max_delta": $scope_pids_max_delta
    }
  }
}
JSON
  echo "Rift wall timeout; supervisor report written to $out" >&2
  exit 1
fi

if [[ ! -s "$tmp_report" ]]; then
  outcome=host_failed_without_report
  signal_json=null
  if [[ "$systemd_result" == "oom-kill" ]] || (( scope_oom_kill_delta > 0 )); then
    outcome=memory_limit
  elif (( scope_pids_max_delta > 0 )); then
    outcome=tasks_limit
  elif [[ $rc -ge 128 && $rc -le 255 ]]; then
    outcome=process_killed
    signal_json=$((rc - 128))
  fi
  cat > "$out" <<JSON
{
  "schema_version": "rift.supervisor.v3",
  "producer": "interdimensional-rift-supervisor",
  "artifact_sha256": "$artifact_sha",
  "artifact_hash_algorithm": "$artifact_hash_algorithm",
  "entry_sha256": "$plugin_sha",
  "execution": {
    "outcome": "$outcome",
    "exit_code": $rc,
    "signal": $signal_json,
    "wall_timeout_seconds": $wall_timeout,
    "exercise_profile": "$exercise_profile",
    "framework_ticks": $framework_ticks,
    "network": "isolated",
    "seccomp": "enforced",
    "systemd_result": "$systemd_result",
    "systemd_exec_main_code": "$systemd_exec_main_code",
    "systemd_exec_main_status": "$systemd_exec_main_status",
    "boundary_profile": "$boundary_profile",
    "contract_mode": "$contract_mode",
    "dalamud_contract": {
      "track": "$contract_track",
      "dalamud_sha256": "$contract_dalamud_sha",
      "tree_sha256": "$contract_tree_sha",
      "hash_algorithm": "$contract_hash_algorithm"
    },
    "tmpfs": {"tmp_bytes": $tmpfs_tmp_bytes, "home_bytes": $tmpfs_home_bytes, "work_bytes": $tmpfs_work_bytes},
    "cgroup": {
      "path": "$scope_cgroup",
      "memory_max": "$memory_max",
      "memory_swap_max": "0",
      "tasks_max": $tasks_max,
      "cpu_quota": "$cpu_quota",
      "memory_oom_kill_delta": $scope_oom_kill_delta,
      "pids_max_delta": $scope_pids_max_delta
    }
  }
}
JSON
  echo "Rift host exited without JSON ($outcome, rc=$rc); supervisor report written to $out" >&2
  exit 1
fi

mv "$tmp_report" "$out"

# A successful managed report is still plugin-process-originated evidence. Emit a
# small trusted-supervisor sidecar outside the hostile cgroup so downstream tools
# can correlate immutable input identity, boundary controls, and the exact report.
report_sha=$(sha256sum "$out" | awk '{print $1}')
if [[ "$out" == *.json ]]; then
  attestation_out="${out%.json}.supervisor-attestation.json"
else
  attestation_out="${out}.supervisor-attestation.json"
fi
cat > "$attestation_out" <<JSON
{
  "schema_version": "rift.supervisor-attestation.v1",
  "producer": "interdimensional-rift-supervisor",
  "outcome": "runtime_report_emitted",
  "runtime_report_sha256": "$report_sha",
  "artifact_tree_sha256": "$artifact_sha",
  "artifact_tree_hash_algorithm": "$artifact_hash_algorithm",
  "entry_sha256": "$plugin_sha",
  "exercise_profile": "$exercise_profile",
  "framework_ticks": $framework_ticks,
  "network": "isolated",
  "seccomp": "enforced",
  "boundary_profile": "$boundary_profile",
  "contract_mode": "$contract_mode",
  "wall_timeout_seconds": $wall_timeout,
  "tmpfs": {"tmp_bytes": $tmpfs_tmp_bytes, "home_bytes": $tmpfs_home_bytes, "work_bytes": $tmpfs_work_bytes},
  "dalamud_contract": {
    "track": "$contract_track",
    "dalamud_sha256": "$contract_dalamud_sha",
    "tree_sha256": "$contract_tree_sha",
    "hash_algorithm": "$contract_hash_algorithm"
  },
  "cgroup": {
    "memory_max": "$memory_max",
    "memory_swap_max": "0",
    "tasks_max": $tasks_max,
    "cpu_quota": "$cpu_quota",
    "memory_oom_kill_delta": $scope_oom_kill_delta,
    "pids_max_delta": $scope_pids_max_delta
  },
  "process_exit_code": $rc
}
JSON

trap - EXIT
sudo systemctl stop "$unit.service" >/dev/null 2>&1 || true
sudo systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
rm -f "$tmp_stderr" "$timeout_marker" "$scope_status"
echo "Rift supervisor attestation written to $attestation_out" >&2
exit "$rc"
