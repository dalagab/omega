#!/usr/bin/env python3
"""Plan the minimal immutable worker-image rebuild set."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SCHEMA = "omega.worker-images.v1"
EXPECTED_IMAGES = (
    "catalog-worker",
    "sigmascope-worker",
    "intelligence-worker",
    "publisher-worker",
    "secondary-security-worker",
)
IMAGE_DOCKERFILES = {
    "catalog-worker": "containers/catalog-worker/Dockerfile",
    "sigmascope-worker": "containers/sigmascope-worker/Dockerfile",
    "intelligence-worker": "containers/intelligence-worker/Dockerfile",
    "publisher-worker": "containers/publisher-worker/Dockerfile",
    "secondary-security-worker": "containers/secondary-security-worker/Dockerfile",
}
GLOBAL_REBUILD_PATHS = {
    ".github/workflows/worker-images.yml",
    "tools/orchestration/publish_worker_images.py",
    "tools/orchestration/worker_image_plan.py",
}


def load_previous(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA:
        raise RuntimeError("previous worker-image manifest schema is unsupported")
    images = document.get("images")
    if not isinstance(images, dict):
        raise RuntimeError("previous worker-image manifest is missing images")
    unknown = set(images) - set(EXPECTED_IMAGES)
    if unknown:
        raise RuntimeError(
            f"previous worker-image manifest contains unexpected images: {sorted(unknown)}"
        )
    return document


def select_images(
    changed_paths: list[str],
    previous_manifest: dict,
    *,
    full_rebuild: bool = False,
) -> list[str]:
    paths = {
        str(path).strip().replace("\\", "/")
        for path in changed_paths
        if str(path).strip()
    }
    previous_images = previous_manifest.get("images") or {}
    if not isinstance(previous_images, dict):
        previous_images = {}

    if full_rebuild or not previous_images or paths & GLOBAL_REBUILD_PATHS:
        return list(EXPECTED_IMAGES)

    selected = set()
    for name, dockerfile in IMAGE_DOCKERFILES.items():
        context = str(Path(dockerfile).parent).replace("\\", "/") + "/"
        if any(path == dockerfile or path.startswith(context) for path in paths):
            selected.add(name)

    selected.update(name for name in EXPECTED_IMAGES if name not in previous_images)

    known_contexts = tuple(
        str(Path(path).parent).replace("\\", "/") + "/"
        for path in IMAGE_DOCKERFILES.values()
    )
    if any(
        path.startswith("containers/") and not path.startswith(known_contexts)
        for path in paths
    ):
        return list(EXPECTED_IMAGES)

    return [name for name in EXPECTED_IMAGES if name in selected]


def build_plan(
    changed_paths: list[str],
    previous_manifest: dict,
    *,
    full_rebuild: bool = False,
) -> dict:
    selected = select_images(
        changed_paths,
        previous_manifest,
        full_rebuild=full_rebuild,
    )
    return {
        "schema": "omega.worker-image-build-plan.v1",
        "selectedImages": selected,
        "buildCount": len(selected),
        "matrix": {
            "include": [
                {
                    "image": name,
                    "dockerfile": IMAGE_DOCKERFILES[name],
                }
                for name in selected
            ]
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-paths", type=Path, required=True)
    parser.add_argument("--previous-manifest", type=Path)
    parser.add_argument("--full-rebuild", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    document = build_plan(
        args.changed_paths.read_text(encoding="utf-8").splitlines(),
        load_previous(args.previous_manifest),
        full_rebuild=args.full_rebuild,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
