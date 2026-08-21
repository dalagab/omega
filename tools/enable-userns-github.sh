#!/usr/bin/env bash
# Enable the unprivileged user-namespace support Bubblewrap requires on an
# ephemeral GitHub-hosted Ubuntu runner. This is intentionally a privileged,
# runner-setup operation and must execute before untrusted plugin material is
# ever made visible to the job.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "error: enable-userns-github.sh must run as root (use sudo)" >&2
  exit 2
fi

# Ubuntu 24.04+ mediates unprivileged user namespaces with AppArmor. Bubblewrap
# upstream currently disables this restriction in its own GitHub Actions CI on
# the disposable runner VM. Keep this change job-local: hosted runners are
# destroyed after the job.
if [[ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
  sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
fi

# Some distributions additionally gate unprivileged user namespaces behind
# this sysctl. Do not ignore a failure: Rift must fail closed if namespaces
# cannot be enabled.
if sysctl -a 2>/dev/null | grep -q '^kernel.unprivileged_userns_clone'; then
  sysctl -w kernel.unprivileged_userns_clone=1
fi

# Make sure at least one user namespace is available to the runner user.
if sysctl -a 2>/dev/null | grep -q '^user.max_user_namespaces'; then
  current=$(sysctl -n user.max_user_namespaces)
  if [[ "$current" -lt 1 ]]; then
    sysctl -w user.max_user_namespaces=1024
  fi
fi
