"""SARIF 2.1.0 rendering."""
import json
import os
import tempfile
import unittest

from apkinspect.report import render_sarif
from apkinspect.scanner import scan_file
from tests import fixtures as fx


class TestSarif(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
        fd, path = tempfile.mkstemp(suffix=".apk")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            cls.doc = json.loads(render_sarif([scan_file(path)]))
        finally:
            os.remove(path)

    def test_envelope(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertEqual(len(self.doc["runs"]), 1)
        self.assertEqual(self.doc["runs"][0]["tool"]["driver"]["name"], "APKInspect")

    def test_rules_and_results_align(self):
        run = self.doc["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertTrue(rule_ids)
        self.assertTrue(run["results"])
        for res in run["results"]:
            self.assertIn(res["ruleId"], rule_ids)
            self.assertIn(res["level"], ("error", "warning", "note", "none"))
            self.assertTrue(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])

    def test_security_severity_present(self):
        for rule in self.doc["runs"][0]["tool"]["driver"]["rules"]:
            self.assertIn("security-severity", rule["properties"])


if __name__ == "__main__":
    unittest.main()
