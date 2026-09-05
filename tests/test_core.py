import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatweaver.core import load_policy, render_markdown, validate  # noqa: E402


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

    def test_requires_every_asvs_chapter(self):
        model = copy.deepcopy(self.model)
        model["asvs_coverage"].pop()
        self.assertTrue(any("missing ASVS coverage chapter: V17" in error for error in validate(model, self.policy)))

    def test_rejects_invalid_framework_references(self):
        model = copy.deepcopy(self.model)
        model["threats"][0]["asvs_refs"] = ["8.4.1"]
        model["threats"][0]["capec_ids"] = ["CAPEC-guessed"]
        errors = validate(model, self.policy)
        self.assertTrue(any("invalid ASVS" in error for error in errors))
        self.assertTrue(any("invalid CAPEC" in error for error in errors))

    def test_report_has_mandatory_register_and_coverage(self):
        report = render_markdown(self.model)
        for heading in ("Existing Security Controls", "Impact", "Security Recommendations", "Severity", "Status", "ASVS 5.0", "CAPEC", "Additional Details"):
            self.assertIn(heading, report)
        self.assertIn("## OWASP ASVS 5.0 coverage", report)


if __name__ == "__main__":
    unittest.main()
