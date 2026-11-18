"""Offline regression tests for model metadata persistence.

Run with: python -m unittest discover -s tests -v
"""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import numpy as np


def load_model_trainer():
    # Import the real trainer without initializing a database, AWS client,
    # document parser or reading the user's .env configuration.
    source = Path(__file__).resolve().parents[1] / "utils" / "model_trainer.py"
    spec = importlib.util.spec_from_file_location("metadata_test_trainer", source)
    module = importlib.util.module_from_spec(spec)
    isolated_modules = {
        name: MagicMock()
        for name in (
            "config", "utils", "utils.db", "utils.aws_helper",
            "utils.feature_extractor",
        )
    }
    with patch.dict(sys.modules, isolated_modules):
        spec.loader.exec_module(module)
    return module.ModelTrainer


ModelTrainer = load_model_trainer()


class ModelMetadataTests(unittest.TestCase):
    def setUp(self):
        self.original_cwd = Path.cwd()
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.addCleanup(os.chdir, self.original_cwd)
        os.chdir(self.workspace.name)
        self.trainer = ModelTrainer()

    def read_metadata(self):
        with open("models/model_meta.json", encoding="utf-8") as stream:
            return json.load(stream)

    def test_saves_training_metrics_as_readable_json(self):
        self.trainer.save_model_metadata(
            accuracy=0.9, test_accuracy=0.95, cv_accuracy=0.9,
            precision=0.91, recall=0.92, f1_score=0.915,
            malware_count=20, clean_count=10,
            class_weights={0: 1.5, 1: 0.75},
        )

        metadata = self.read_metadata()
        self.assertEqual(metadata["model_version"], "2.3")
        self.assertTrue(metadata["trained_at"].endswith(" UTC"))
        self.assertEqual(metadata["accuracy"], 0.9)
        self.assertEqual(metadata["test_accuracy"], 0.95)
        self.assertEqual(metadata["cv_accuracy"], 0.9)
        self.assertEqual(metadata["malware_count"], 20)
        self.assertEqual(metadata["clean_count"], 10)
        self.assertEqual(metadata["class_weights"], {"0": 1.5, "1": 0.75})

    def test_serializes_numpy_metrics_and_arrays(self):
        self.trainer.save_model_metadata(
            accuracy=np.float64(0.9),
            precision=np.float32(0.875),
            confusion_matrix=np.array([[8, 2], [1, 19]]),
        )

        metadata = self.read_metadata()
        self.assertEqual(metadata["accuracy"], 0.9)
        self.assertEqual(metadata["precision"], 0.875)
        self.assertEqual(metadata["confusion_matrix"], [[8, 2], [1, 19]])


if __name__ == "__main__":
    unittest.main()
