from __future__ import annotations

import unittest

from tools.orchestration import worker_image_plan


class WorkerImagePlanTests(unittest.TestCase):
    def previous(self) -> dict:
        return {
            "schema": worker_image_plan.SCHEMA,
            "images": {
                name: f"ghcr.io/example/{name}@sha256:" + ("a" * 64)
                for name in worker_image_plan.EXPECTED_IMAGES
            },
        }

    def test_rebuilds_only_changed_image(self) -> None:
        self.assertEqual(
            ["intelligence-worker"],
            worker_image_plan.select_images(
                ["containers/intelligence-worker/Dockerfile"],
                self.previous(),
            ),
        )

    def test_bootstraps_missing_secondary_security_image(self) -> None:
        previous = self.previous()
        previous["images"].pop("secondary-security-worker")
        self.assertEqual(
            ["sigmascope-worker", "secondary-security-worker"],
            worker_image_plan.select_images(
                ["containers/sigmascope-worker/Dockerfile"],
                previous,
            ),
        )

    def test_worker_image_workflow_change_rebuilds_everything(self) -> None:
        self.assertEqual(
            list(worker_image_plan.EXPECTED_IMAGES),
            worker_image_plan.select_images(
                [".github/workflows/worker-images.yml"],
                self.previous(),
            ),
        )


if __name__ == "__main__":
    unittest.main()
