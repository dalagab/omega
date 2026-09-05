#!/usr/bin/env bash
set -euo pipefail

mkdir -p catalog/slot-work
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-$PWD/catalog/slot-work/gitconfig}"
git config --global --add safe.directory "$PWD"
git config --global --add safe.directory "$PWD/catalog/active-state"
git config --global --add safe.directory "$PWD/catalog/security-v2-current"

case "${1:-}" in
  bind)
    current="$(git -C catalog/security-v2-current rev-parse HEAD)"
    test "$current" = "$BASE_EVIDENCE_HEAD" || {
      echo "::error::Evidence moved after drain planning: planned=$BASE_EVIDENCE_HEAD current=$current"
      exit 3
    }
    python "$OMEGA_FROZEN_WORKER/tools/catalog/definitions_snapshot.py" \
      verify-worker --definitions-root catalog/active-state/definitions
    pipeline="$OMEGA_FROZEN_WORKER/tools/security/production_sigmascope_v2_pipeline.py"
    python "$pipeline" --help 2>&1 | grep -q -- '--queue-key' || {
      echo "::error::Frozen Definitions worker lacks exact queue-key execution."
      exit 4
    }
    yara --version
    clamscan --version || true
    ;;
  materialize-assets)
    python "$OMEGA_FROZEN_WORKER/tools/catalog/secondary_security_assets.py" materialize-clamav \
      --definitions-root catalog/active-state/definitions \
      --output "$OMEGA_SECONDARY_SECURITY_CACHE"
    ;;
  materialize-catalog)
    definitions_revision="$(jq -r '.definitionsRevision' catalog/active-state/definitions/index.json)"
    python "$OMEGA_FROZEN_WORKER/tools/catalog/catalog_json_store.py" materialize \
      --root catalog/active-state/catalog \
      --database catalog/security-input/omega-catalog.sqlite \
      --definitions-revision "$definitions_revision"
    ;;
  process)
    mkdir -p catalog/slot-result-bundles catalog/slot-work
    python - <<'PY' > catalog/slot-work/queue-keys.txt
import json, os
keys = json.loads(os.environ["QUEUE_KEYS_JSON"])
if not isinstance(keys, list) or not keys:
    raise SystemExit("worker slot has no queue keys")
if len(keys) > 16 or len(keys) != len(set(keys)):
    raise SystemExit("worker slot queue-key set is invalid")
for key in keys:
    text = str(key)
    if not text or "\n" in text or "\r" in text:
        raise SystemExit("unsafe queue key")
    print(text)
PY
    defs=catalog/active-state/definitions/index.json
    catalog_index=catalog/active-state/catalog/index.json
    pipeline="$OMEGA_FROZEN_WORKER/tools/security/production_sigmascope_v2_pipeline.py"
    candidate=catalog/slot-work/candidate
    work=catalog/slot-work/work
    rm -rf "$candidate" "$work" catalog/slot-result-bundles catalog/slot-work/bundle-reports
    mkdir -p catalog/slot-result-bundles

    python tools/security/sigmascope_worker_batch.py run \
      --pipeline "$pipeline" \
      --queue-keys-file catalog/slot-work/queue-keys.txt \
      -- \
      --base-database catalog/security-input/omega-catalog.sqlite \
      --current-evidence catalog/security-v2-current \
      --candidate-evidence "$candidate" \
      --work-dir "$work" \
      --skip-marketplace \
      --frozen-advisories catalog/active-state/definitions/osv-advisories.json \
      --frozen-definitions catalog/active-state/definitions \
      --catalog-revision "$(jq -r '.catalogRevision' "$catalog_index")" \
      --definitions-revision "$(jq -r '.definitionsRevision' "$defs")" \
      --scanner-revision "$(jq -r '.scannerRevision' "$defs")" \
      --artifact-analysis-revision "$(jq -r '.artifactAnalysisRevision' "$defs")" \
      --source-analysis-revision "$(jq -r '.sourceAnalysisRevision' "$defs")" \
      --scanner-bundle-sha256 "$(jq -r '.scannerBundle.sha256' "$defs")" \
      --rule-set-revision "$(jq -r '.ruleSetRevision' "$defs")" \
      --advisory-revision "$(jq -r '.advisoryRevision' "$defs")" \
      --queue-seed catalog/roboscope-plan/roboscope-effective-scan-queue.json \
      --evidence-index-url "https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/security-evidence-v2/index.json" \
      --max-batch-seconds 3000 \
      --source-overrides "$OMEGA_FROZEN_WORKER/sources/source-overrides.json"

    python tools/security/sigmascope_worker_batch.py bundles \
      --current-evidence catalog/security-v2-current \
      --candidate-evidence "$candidate" \
      --work-dir "$work" \
      --definitions-root catalog/active-state/definitions \
      --queue-keys-file catalog/slot-work/queue-keys.txt \
      --worker-image "$WORKER_IMAGE" \
      --output-root catalog/slot-result-bundles \
      --split-work-root catalog/slot-work/bundle-reports
    ;;
  *)
    echo "usage: $0 {bind|materialize-assets|materialize-catalog|process}" >&2
    exit 2
    ;;
esac