"""Baseline suppression: fingerprints, write/load, and scan-time suppression."""
import os
import tempfile
import unittest

from apkinspect import baseline
from apkinspect.model import Finding
from apkinspect.scanner import scan_file
from tests import fixtures as fx


class TestFingerprint(unittest.TestCase):
    def test_ignores_severity_and_category(self):
        a = Finding("X", "same title", "HIGH", "config", location="app", evidence="e")
        b = Finding("X", "same title", "LOW", "secret", location="app", evidence="e")
        self.assertEqual(baseline.fingerprint(a), baseline.fingerprint(b))

    def test_distinguishes_title(self):
        a = Finding("PERMISSION_DANGEROUS", "Requests permission: READ_SMS", "MEDIUM", "permission",
                    location="manifest")
        b = Finding("PERMISSION_DANGEROUS", "Requests permission: CAMERA", "LOW", "permission",
                    location="manifest")
        self.assertNotEqual(baseline.fingerprint(a), baseline.fingerprint(b))


class TestSuppression(unittest.TestCase):
    def test_write_then_suppress(self):
        data = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
        fd, apk = tempfile.mkstemp(suffix=".apk")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        bl = apk + ".baseline.json"
        try:
            full = scan_file(apk)
            self.assertTrue(full.findings)
            count = baseline.write(bl, [full])
            self.assertGreater(count, 0)

            suppressed = scan_file(apk, suppress=baseline.load(bl))
            self.assertEqual(suppressed.findings, [])
            self.assertEqual(suppressed.score, 100)
            self.assertEqual(suppressed.meta.get("suppressed_count"), len(full.findings))
        finally:
            os.remove(apk)
            if os.path.exists(bl):
                os.remove(bl)


if __name__ == "__main__":
    unittest.main()
