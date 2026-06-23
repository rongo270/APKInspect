"""CLI behaviour: output formats and exit codes."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from apkinspect.__main__ import main
from tests import fixtures as fx


def write_tmp(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


class TestCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vuln = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
        clean = fx.build_apk_bytes(fx.clean_manifest(), fx.clean_dex())
        cls.vuln = write_tmp(vuln, ".apk")
        cls.clean = write_tmp(clean, ".apk")

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.vuln)
        os.remove(cls.clean)

    def run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_text_report_runs(self):
        code, out = self.run_cli([self.vuln, "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("SAFETY SCORE", out)
        self.assertIn("com.apkinspect.vulnerable", out)

    def test_json_output(self):
        code, out = self.run_cli([self.vuln, "--json"])
        data = json.loads(out)
        self.assertIn("score", data)
        self.assertEqual(data["file_type"], "apk")
        self.assertTrue(data["findings"])

    def test_min_score_gate_fails(self):
        code, _ = self.run_cli([self.vuln, "--json", "--min-score", "90"])
        self.assertEqual(code, 1)

    def test_min_score_gate_passes_clean(self):
        code, _ = self.run_cli([self.clean, "--json", "--min-score", "80"])
        self.assertEqual(code, 0)

    def test_fail_on_high(self):
        code, _ = self.run_cli([self.vuln, "--json", "--fail-on", "HIGH"])
        self.assertEqual(code, 1)

    def test_multiple_files_json_is_list(self):
        code, out = self.run_cli([self.vuln, self.clean, "--json"])
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)


if __name__ == "__main__":
    unittest.main()
