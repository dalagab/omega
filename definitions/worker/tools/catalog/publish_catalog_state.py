#!/usr/bin/env python3
"""Atomically publish validated catalog state with controlled Git history.

Catalog freezes are meaningful release boundaries, so each changed authoritative snapshot
defaults to a normal fast-forward commit whose parent is the exact current ``catalog-data``
head. The pre-migration orphan/force-with-lease mode remains available only as an explicit
emergency fallback. Unchanged trees are publication no-ops.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import catalog_state  # noqa: E402

ORCHESTRATION_DIR = SCRIPT_DIR.parent / "orchestration"
if str(ORCHESTRATION_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATION_DIR))
from git_snapshot_history import HISTORY_FAST_FORWARD, HISTORY_MODES, publish_snapshot_tree  # noqa: E402


def publish(
    source: Path,
    repo: Path,
    branch: str,
    remote: str,
    push: bool,
    *,
    history_mode: str = HISTORY_FAST_FORWARD,
) -> dict:
    source = source.resolve()
    validation = catalog_state.validate(source)
    if not validation.get("ok"):
        raise RuntimeError("catalog-state validation failed: " + "; ".join(validation.get("errors") or []))
    index = json.loads((source / "index.json").read_text(encoding="utf-8"))
    publication = publish_snapshot_tree(
        source,
        repo=repo.resolve(),
        remote=remote,
        branch=branch,
        push=push,
        author_name="Omega Catalog Publisher",
        author_email="omega-catalog@users.noreply.github.com",
        commit_message=f"Catalog state {index.get('stateRevision','snapshot')}",
        history_mode=history_mode,
    )
    result = {**validation, "branch": branch}
    result.update(publication.as_dict())
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--branch", default="catalog-data")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--history-mode", choices=HISTORY_MODES, default=HISTORY_FAST_FORWARD,
                        help="Authoritative publication history mode (default: controlled fast-forward)")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    print(json.dumps(publish(args.input, args.repo, args.branch, args.remote, args.push, history_mode=args.history_mode), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
