import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatweaver.core import load_policy, validate  # noqa: E402


class ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = json.loads((ROOT / "examples" / "sample-model.json").read_text(encoding="utf-8"))
        cls.policy = load_policy(ROOT / "config" / "risk-policy.json")

    def test_sample_is_valid(self):
        self.assertEqual([], validate(copy.deepcopy(self.model), self.policy))

    def test_rejects_wrong_severity(self):
        model = copy.deepcopy(self.model)
        model["threats"][0]["severity"] = "low"
        self.assertTrue(any("expected high" in error for error in validate(model, self.policy)))

    def test_rejects_unknown_evidence(self):
        model = copy.deepcopy(self.model)
        model["threats"][0]["evidence_refs"] = ["E-999"]
        self.assertTrue(any("unknown evidence" in error for error in validate(model, self.policy)))

    def test_rejects_unknown_component(self):
        model = copy.deepcopy(self.model)
        model["threats"][0]["component_refs"] = ["C-999"]
        self.assertTrue(any("unknown component" in error for error in validate(model, self.policy)))


if __name__ == "__main__":
    unittest.main()
