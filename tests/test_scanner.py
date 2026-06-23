"""End-to-end scanning of synthetic APK/AAB archives."""
import os
import tempfile
import unittest

from apkinspect.scanner import scan_file
from tests import fixtures as fx


def write_tmp(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


class TestVulnerableApk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
        cls.path = write_tmp(data, ".apk")
        cls.result = scan_file(cls.path)
        cls.ids = {f.id for f in cls.result.findings}

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.path)

    def test_type_and_package(self):
        self.assertEqual(self.result.file_type, "apk")
        self.assertEqual(self.result.package, "com.apkinspect.vulnerable")

    def test_secrets_found(self):
        for sid in ("SECRET_GOOGLE_API_KEY", "SECRET_AWS_ACCESS_KEY_ID",
                    "SECRET_FIREBASE_DB_URL", "SECRET_PRIVATE_KEY", "SECRET_SLACK_TOKEN"):
            self.assertIn(sid, self.ids, sid)

    def test_manifest_issues_found(self):
        for mid in ("MANIFEST_DEBUGGABLE", "MANIFEST_CLEARTEXT", "COMPONENT_HTTP_DEEPLINK",
                    "COMPONENT_EXPORTED", "PERMISSION_DANGEROUS"):
            self.assertIn(mid, self.ids, mid)

    def test_maps_key_from_manifest(self):
        locs = [f.location for f in self.result.findings if f.id == "SECRET_GOOGLE_API_KEY"]
        self.assertTrue(any("AndroidManifest.xml" in l for l in locs))

    def test_secret_is_redacted(self):
        pk = [f for f in self.result.findings if f.id == "SECRET_PRIVATE_KEY"][0]
        self.assertNotIn("MIIBOgIBAAJBAKj", pk.evidence)

    def test_low_score(self):
        self.assertLess(self.result.score, 50)
        self.assertIn(self.result.grade, ("D", "F"))


class TestCleanApk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = fx.build_apk_bytes(fx.clean_manifest(), fx.clean_dex())
        cls.path = write_tmp(data, ".apk")
        cls.result = scan_file(cls.path)
        cls.ids = {f.id for f in cls.result.findings}

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.path)

    def test_high_score(self):
        self.assertGreaterEqual(self.result.score, 80)
        self.assertIn(self.result.grade, ("A", "B"))

    def test_no_secrets(self):
        self.assertFalse(any(f.category == "secret" for f in self.result.findings))


class TestAab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = fx.build_aab_bytes(fx.planted_dex())
        cls.path = write_tmp(data, ".aab")
        cls.result = scan_file(cls.path)
        cls.ids = {f.id for f in cls.result.findings}

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.path)

    def test_type_and_package(self):
        self.assertEqual(self.result.file_type, "aab")
        self.assertEqual(self.result.package, "com.apkinspect.aab")

    def test_findings(self):
        self.assertIn("MANIFEST_DEBUGGABLE", self.ids)
        self.assertIn("SECRET_AWS_ACCESS_KEY_ID", self.ids)


class TestErrorHandling(unittest.TestCase):
    def test_not_an_archive(self):
        path = write_tmp(b"this is plainly not a zip archive", ".apk")
        try:
            result = scan_file(path)
            self.assertEqual(result.score, 0)
            self.assertTrue(result.errors)
        finally:
            os.remove(path)

    def test_missing_file(self):
        result = scan_file("/no/such/file.apk")
        self.assertEqual(result.score, 0)
        self.assertIn("file not found", result.errors)


if __name__ == "__main__":
    unittest.main()
