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
    [--request-id <broker-request-id> --variant-id <id> --artifact-sha256 <sha256>] \
    --plugin <entry-plugin.dll> \
    --artifact-dir <exact-staged-artifact-dir> \
    [--seed-config-dir <explicit-read-only-plugin-config>] \
    [--game-data-fixture-dir <synthetic-read-only-game-data-pack>] \
    [--ui-profile none|headless-ui-v1] \
    [--network-profile isolated-v1|isolated-observed-v1] \
    --seccomp-policy <rift-policy.bpf> \
    --out <report.json> \
    [--observer-out <outer-observer.json>] \
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
seed_config_dir=''
game_data_fixture_dir=''
seccomp_policy=''
out=''
observer_out=''
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
request_id=''
variant_id=''
request_artifact_sha256=''
exercise_profile=post-init-safe-v1
ui_profile=none
network_profile=isolated-v1
framework_ticks=3
BWRAP=${BWRAP:-$(command -v bwrap || true)}
CC=${CC:-cc}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-dir) runtime_dir=${2:-}; shift 2 ;;
    --contract-dir) contract_dir=${2:-}; shift 2 ;;
    --contract-track) contract_track=${2:-}; shift 2 ;;
    --request-id) request_id=${2:-}; shift 2 ;;
    --variant-id) variant_id=${2:-}; shift 2 ;;
    --artifact-sha256) request_artifact_sha256=${2:-}; shift 2 ;;
    --plugin) plugin=${2:-}; shift 2 ;;
    --artifact-dir) artifact_dir=${2:-}; shift 2 ;;
    --seed-config-dir) seed_config_dir=${2:-}; shift 2 ;;
    --game-data-fixture-dir) game_data_fixture_dir=${2:-}; shift 2 ;;
    --seccomp-policy) seccomp_policy=${2:-}; shift 2 ;;
    --out) out=${2:-}; shift 2 ;;
    --observer-out) observer_out=${2:-}; shift 2 ;;
    --init-timeout) init_timeout=${2:-}; shift 2 ;;
    --exercise-profile) exercise_profile=${2:-}; shift 2 ;;
    --ui-profile) ui_profile=${2:-}; shift 2 ;;
    --network-profile) network_profile=${2:-}; shift 2 ;;
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
[[ -z "$seed_config_dir" || -d "$seed_config_dir" ]] || { echo "error: --seed-config-dir must be a directory" >&2; exit 2; }
[[ -z "$game_data_fixture_dir" || -d "$game_data_fixture_dir" ]] || { echo "error: --game-data-fixture-dir must be a directory" >&2; exit 2; }
[[ -n "$seccomp_policy" && -s "$seccomp_policy" ]] || { echo "error: --seccomp-policy is required" >&2; exit 2; }
[[ -n "$out" ]] || { echo "error: --out is required" >&2; exit 2; }
[[ "$init_timeout" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "error: invalid --init-timeout" >&2; exit 2; }
[[ "$exercise_profile" == "post-init-safe-v1" || "$exercise_profile" == "none" ]] || { echo "error: invalid --exercise-profile" >&2; exit 2; }
[[ "$ui_profile" == "none" || "$ui_profile" == "headless-ui-v1" ]] || { echo "error: --ui-profile must be none or headless-ui-v1" >&2; exit 2; }
[[ "$network_profile" == "isolated-v1" || "$network_profile" == "isolated-observed-v1" ]] || { echo "error: invalid --network-profile" >&2; exit 2; }
[[ "$framework_ticks" =~ ^[0-9]+$ && "$framework_ticks" -le 32 ]] || { echo "error: invalid --framework-ticks" >&2; exit 2; }
[[ "$wall_timeout" =~ ^[0-9]+$ && "$wall_timeout" -gt 0 ]] || { echo "error: invalid --wall-timeout" >&2; exit 2; }
[[ "$memory_max" =~ ^[0-9]+([KMGTP])?$ ]] || { echo "error: invalid --memory-max" >&2; exit 2; }
[[ "$tasks_max" =~ ^[0-9]+$ && "$tasks_max" -gt 0 ]] || { echo "error: invalid --tasks-max" >&2; exit 2; }
[[ "$cpu_quota" =~ ^[0-9]+%$ ]] || { echo "error: invalid --cpu-quota" >&2; exit 2; }

request_binding_count=0
[[ -n "$request_id" ]] && request_binding_count=$((request_binding_count + 1))
[[ -n "$variant_id" ]] && request_binding_count=$((request_binding_count + 1))
[[ -n "$request_artifact_sha256" ]] && request_binding_count=$((request_binding_count + 1))
if [[ "$request_binding_count" -ne 0 && "$request_binding_count" -ne 3 ]]; then
  echo "error: --request-id, --variant-id, and --artifact-sha256 must be supplied together" >&2
  exit 2
fi
if [[ "$request_binding_count" -eq 3 ]]; then
  [[ "$variant_id" =~ ^[1-9][0-9]*$ ]] || { echo "error: invalid --variant-id" >&2; exit 2; }
  [[ "$request_artifact_sha256" =~ ^[0-9a-f]{64}$ ]] || { echo "error: invalid --artifact-sha256" >&2; exit 2; }
  python3 - "$request_id" <<'PY_REQUEST_ID'
import re, sys
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,159}', sys.argv[1]):
    raise SystemExit('error: invalid --request-id')
PY_REQUEST_ID
fi

for command in systemd-run systemctl sudo timeout sha256sum realpath python3 "$CC"; do
  command -v "$command" >/dev/null 2>&1 || { echo "error: $command is required" >&2; exit 2; }
done
[[ -n "$BWRAP" && -x "$BWRAP" ]] || { echo "error: bwrap is required" >&2; exit 2; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
launcher="$root/tools/exec-bwrap-seccomp.sh"
scope_runner="$root/tools/exec-rift-scope.sh"
loopback_probe_source="$root/tools/sandbox-probes/rift-loopback-probe.c"
headless_imgui_builder="$root/tools/build-headless-cimgui.py"
game_data_fixture_validator="$root/tools/validate-rift-game-data-fixture.py"
[[ -f "$launcher" && -f "$scope_runner" && -s "$loopback_probe_source" ]] || { echo "error: Rift supervisor helpers missing" >&2; exit 2; }
[[ "$ui_profile" != "headless-ui-v1" || -s "$headless_imgui_builder" ]] || { echo "error: Rift headless UI builder missing" >&2; exit 2; }
[[ -z "$game_data_fixture_dir" || -s "$game_data_fixture_validator" ]] || { echo "error: Rift game-data fixture validator missing" >&2; exit 2; }

runtime_dir=$(realpath "$runtime_dir")
contract_dir=$(realpath "$contract_dir")
plugin=$(realpath "$plugin")
artifact_dir=$(realpath "$artifact_dir")
artifact_mount_dir=$artifact_dir
artifact_parent=$(dirname "$artifact_dir")
headless_artifact_dir=''
headless_imgui_sha=''
if [[ -n "$seed_config_dir" ]]; then
  seed_config_dir=$(realpath "$seed_config_dir")
fi
if [[ -n "$game_data_fixture_dir" ]]; then
  game_data_fixture_dir=$(realpath "$game_data_fixture_dir")
fi
seccomp_policy=$(realpath "$seccomp_policy")
BWRAP=$(realpath "$BWRAP")
out=$(realpath -m "$out")
mkdir -p "$(dirname "$out")"
if [[ -n "$observer_out" ]]; then
  command -v strace >/dev/null 2>&1 || { echo "error: strace is required with --observer-out" >&2; exit 2; }
  observer_out=$(realpath -m "$observer_out")
  mkdir -p "$(dirname "$observer_out")"
fi
[[ "$network_profile" != "isolated-observed-v1" || -n "$observer_out" ]] || { echo "error: --network-profile isolated-observed-v1 requires --observer-out" >&2; exit 2; }

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
seed_config_json='null'
if [[ -n "$seed_config_dir" ]]; then
  seed_config_sha=$(python3 "$root/tools/hash-artifact-tree.py" "$seed_config_dir")
  seed_config_json="{\"tree_sha256\": \"$seed_config_sha\", \"hash_algorithm\": \"$artifact_hash_algorithm\"}"
fi
game_data_fixture_json='null'
if [[ -n "$game_data_fixture_dir" ]]; then
  python3 "$game_data_fixture_validator" "$game_data_fixture_dir"
  game_data_fixture_sha=$(python3 "$root/tools/hash-artifact-tree.py" "$game_data_fixture_dir")
  game_data_fixture_json="{\"tree_sha256\": \"$game_data_fixture_sha\", \"hash_algorithm\": \"$artifact_hash_algorithm\", \"real_game_data\": false}"
fi

tmp_report=$(mktemp)
tmp_stderr=$(mktemp)
observer_trace_dir=$(mktemp -d)
loopback_probe_bin=$(mktemp)
headless_imgui_lib=$(mktemp)
timeout_marker=$(mktemp)
scope_status=$(mktemp)
rm -f "$timeout_marker" "$scope_status"
unit="rift-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
cleanup() {
  sudo systemctl stop "$unit.service" >/dev/null 2>&1 || true
  sudo systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  rm -f "$tmp_report" "$tmp_stderr" "$loopback_probe_bin" "$headless_imgui_lib" "$timeout_marker" "$scope_status"
  rm -rf "$observer_trace_dir" "$headless_artifact_dir"
}
trap cleanup EXIT

"$CC" -std=c11 -O2 -Wall -Wextra -Werror "$loopback_probe_source" -o "$loopback_probe_bin" || {
  echo "error: unable to build the trusted dynamic loopback probe" >&2
  exit 2
}
chmod 0555 "$loopback_probe_bin"
if [[ "$ui_profile" == "headless-ui-v1" ]]; then
  python3 "$headless_imgui_builder" \
    --binding "$contract_dir/Dalamud.Bindings.ImGui.dll" \
    --out "$headless_imgui_lib" \
    --cc "$CC" || {
      echo "error: unable to build Rift's headless cimgui shim" >&2
      exit 2
    }
  # Dalamud.Bindings.ImGui resolves its native library beside the loaded plugin
  # artifact. Keep the original artifact hash immutable and mount an ephemeral
  # overlay containing only the trusted, inert cimgui symbol shim.
  headless_imgui_sha=$(sha256sum "$headless_imgui_lib" | awk '{print $1}')
  headless_artifact_dir=$(mktemp -d "$artifact_parent/.rift-headless-artifact.XXXXXX")
  cp -al "$artifact_dir/." "$headless_artifact_dir"
  cp "$headless_imgui_lib" "$headless_artifact_dir/cimgui.dll"
  artifact_mount_dir=$headless_artifact_dir
fi

supports_disable_userns=false
if "$BWRAP" --help 2>&1 | grep -q -- '--disable-userns'; then
  supports_disable_userns=true
else
  boundary_profile=rift-linux-bwrap-v3-seccomp-userns
fi

bwrap_args=(
  --unshare-user
  --unshare-ipc
  --unshare-pid
  --unshare-net
  --unshare-uts
  --unshare-cgroup-try
  --new-session
  --die-with-parent
  --cap-drop ALL
  --clearenv
  --hostname interdimensional-rift
  --ro-bind "$runtime_dir" /rift
  --ro-bind "$contract_dir" /contracts
  --ro-bind "$artifact_mount_dir" /input
  --dir /rift-tools
  --ro-bind "$loopback_probe_bin" /rift-tools/rift-loopback-probe
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
  --setenv RIFT_NETWORK_PROFILE "$network_profile"
  --setenv RIFT_DYNAMIC_LOOPBACK_PROBE dynamic-v1
  --setenv RIFT_BOOTSTRAP_TRACE 1
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
  --setenv RIFT_UI_PROFILE "$ui_profile"
  --setenv RIFT_HEADLESS_UI_SHIM_SHA256 "$headless_imgui_sha"
  --setenv RIFT_HEADLESS_UI_SHIM_PATH "cimgui.dll"
  --setenv RIFT_FRAMEWORK_TICKS "$framework_ticks"
  --chdir /work
)

if [[ -n "$seed_config_dir" ]]; then
  bwrap_args+=(
    --dir /rift-seed-config
    --ro-bind "$seed_config_dir" /rift-seed-config
    --setenv RIFT_SEED_CONFIG_DIR /rift-seed-config
    --setenv RIFT_SEED_CONFIG_TREE_SHA256 "$seed_config_sha"
  )
fi

if [[ -n "$game_data_fixture_dir" ]]; then
  bwrap_args+=(
    --dir /rift-game-data
    --ro-bind "$game_data_fixture_dir" /rift-game-data
    --setenv RIFT_GAME_DATA_FIXTURE_DIR /rift-game-data
    --setenv RIFT_GAME_DATA_FIXTURE_TREE_SHA256 "$game_data_fixture_sha"
  )
fi

if [[ "$supports_disable_userns" == true ]]; then
  bwrap_args+=(--disable-userns)
fi

sandbox_command=(/rift-tools/rift-loopback-probe --duration-ms "$((wall_timeout * 1000))" --connect-timeout-ms 250 -- "$host_bin" "/input/$plugin_rel" --timeout "$init_timeout" --exercise-profile "$exercise_profile" --framework-ticks "$framework_ticks" --no-color)
supervised_command=(/bin/bash "$scope_runner" "$timeout_marker" "$scope_status" "$wall_timeout" /bin/bash "$launcher" "$seccomp_policy" "$BWRAP" "${bwrap_args[@]}" -- "${sandbox_command[@]}")
if [[ -n "$observer_out" ]]; then
  supervised_command=(strace -ff -qq -s 512 -o "$observer_trace_dir/trace" -e trace=%file,%process,network "${supervised_command[@]}")
fi

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
  "${supervised_command[@]}" \
  >"$tmp_report" 2>"$tmp_stderr"
rc=$?
set -e

if [[ -n "$observer_out" ]]; then
  python3 "$root/tools/collect-rift-observer.py" \
    --trace-dir "$observer_trace_dir" \
    --out "$observer_out" \
    --artifact-tree-sha256 "$artifact_sha"
fi

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
    "ui_profile": "$ui_profile",
    "framework_ticks": $framework_ticks,
    "network": "isolated",
    "network_profile": "$network_profile",
    "seed_config": $seed_config_json,
    "game_data_fixture": $game_data_fixture_json,
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
    "ui_profile": "$ui_profile",
    "framework_ticks": $framework_ticks,
    "network": "isolated",
    "network_profile": "$network_profile",
    "seed_config": $seed_config_json,
    "game_data_fixture": $game_data_fixture_json,
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
attestation_schema='rift.supervisor-attestation.v1'
omega_request_json='null'
if [[ "$request_binding_count" -eq 3 ]]; then
  attestation_schema='rift.supervisor-attestation.v2'
  omega_request_json=$(python3 - "$request_id" "$variant_id" "$request_artifact_sha256" <<'PY_OMEGA_REQUEST'
import json, sys
print(json.dumps({
    "request_id": sys.argv[1],
    "variant_id": int(sys.argv[2]),
    "artifact_sha256": sys.argv[3],
}, separators=(',', ':')))
PY_OMEGA_REQUEST
)
fi
if [[ "$out" == *.json ]]; then
  attestation_out="${out%.json}.supervisor-attestation.json"
else
  attestation_out="${out}.supervisor-attestation.json"
fi
cat > "$attestation_out" <<JSON
{
  "schema_version": "$attestation_schema",
  "producer": "interdimensional-rift-supervisor",
  "outcome": "runtime_report_emitted",
  "runtime_report_sha256": "$report_sha",
  "omega_request": $omega_request_json,
  "artifact_tree_sha256": "$artifact_sha",
  "artifact_tree_hash_algorithm": "$artifact_hash_algorithm",
  "entry_sha256": "$plugin_sha",
  "exercise_profile": "$exercise_profile",
  "ui_profile": "$ui_profile",
  "framework_ticks": $framework_ticks,
  "network": "isolated",
  "network_profile": "$network_profile",
  "seed_config": $seed_config_json,
  "game_data_fixture": $game_data_fixture_json,
  "dynamic_loopback_probe": "dynamic-v1",
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
rm -f "$loopback_probe_bin"
rm -f "$headless_imgui_lib"
rm -rf "$observer_trace_dir"
echo "Rift supervisor attestation written to $attestation_out" >&2
exit "$rc"
