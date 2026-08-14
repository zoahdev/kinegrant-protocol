from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DeploymentExampleTests(unittest.TestCase):
    def _load(self, module_path: str) -> object:
        path = ROOT / module_path
        sys.path.insert(0, str(path.parent))
        try:
            import importlib.util

            spec = importlib.util.spec_from_file_location(path.stem, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            sys.path.pop(0)

    def test_home_robot_example(self) -> None:
        module = self._load("examples/home-robot/home_robot.py")
        trace = module.run()
        self.assertTrue(trace["passed"])

    def test_camera_consent_example(self) -> None:
        module = self._load("examples/camera-consent/camera_consent.py")
        trace = module.run()
        self.assertTrue(trace["passed"])


if __name__ == "__main__":
    unittest.main()
