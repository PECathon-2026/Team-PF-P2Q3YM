import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from privacylens.paths import PROJECT_ROOT, RUN_DIR_ENV, get_run_output_dir


class RunPathTests(unittest.TestCase):
    def test_default_and_configured_locations_are_outside_project(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(RUN_DIR_ENV, None)
            default = get_run_output_dir()
        self.assertFalse(default.is_relative_to(PROJECT_ROOT))
        with tempfile.TemporaryDirectory() as tmp:
            configured_path = Path(tmp) / "artifacts"
            with patch.dict(os.environ, {RUN_DIR_ENV: str(configured_path)}):
                self.assertEqual(get_run_output_dir(), configured_path.resolve())

    def test_project_local_run_directory_is_rejected(self):
        with patch.dict(os.environ, {RUN_DIR_ENV: str(PROJECT_ROOT / "runs")}):
            with self.assertRaises(ValueError):
                get_run_output_dir()


if __name__ == "__main__": unittest.main()
