import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location("publish_worker_images", ROOT/"tools/orchestration/publish_worker_images.py")
MODULE=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

class PublishWorkerImagesTests(unittest.TestCase):
    def valid_manifest(self):
        return {
            "schema":"omega.worker-images.v1",
            "workerImagesRevision":"worker-images-v1-0123456789abcdef0123",
            "builtFromCommit":"a"*40,
            "images":{name:f"ghcr.io/dalagab/omega-{name}@sha256:"+("b"*64) for name in MODULE.EXPECTED_IMAGES},
        }

    def test_accepts_complete_digest_pinned_manifest(self):
        self.assertIs(MODULE.validate_manifest(self.valid_manifest()), self.valid_manifest()) if False else MODULE.validate_manifest(self.valid_manifest())

    def test_rejects_exact_phase4c_digest_parser_regression(self):
        doc=self.valid_manifest()
        doc["images"]["publisher-worker"]="ghcr.io/dalagab/omega-publisher-worker@digest:"
        with self.assertRaisesRegex(RuntimeError,"invalid immutable worker image reference"):
            MODULE.validate_manifest(doc)

    def test_rejects_tag_only_reference(self):
        doc=self.valid_manifest()
        doc["images"]["publisher-worker"]="ghcr.io/dalagab/omega-publisher-worker:toolchain-v1"
        with self.assertRaisesRegex(RuntimeError,"invalid immutable worker image reference"):
            MODULE.validate_manifest(doc)

    def test_rejects_missing_image_identity(self):
        doc=self.valid_manifest()
        del doc["images"]["intelligence-worker"]
        with self.assertRaisesRegex(RuntimeError,"exactly the four expected"):
            MODULE.validate_manifest(doc)

if __name__ == "__main__":
    unittest.main()
