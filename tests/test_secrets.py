"""Secret/API-key detection and redaction."""
import unittest

from apkinspect import secrets
from tests import fixtures as fx


def ids(findings):
    return {f.id for f in findings}


class TestSecretScanning(unittest.TestCase):
    def test_finds_planted_secrets(self):
        text = fx.planted_dex().decode("latin-1")
        found = ids(secrets.scan_text(text, "classes.dex"))
        self.assertIn("SECRET_GOOGLE_API_KEY", found)
        self.assertIn("SECRET_AWS_ACCESS_KEY_ID", found)
        self.assertIn("SECRET_FIREBASE_DB_URL", found)
        self.assertIn("SECRET_PRIVATE_KEY", found)
        self.assertIn("SECRET_SLACK_TOKEN", found)

    def test_firebase_is_network_category(self):
        f = [x for x in secrets.scan_text(fx.FIREBASE_DB, "x") if x.id == "SECRET_FIREBASE_DB_URL"][0]
        self.assertEqual(f.category, "network")
        self.assertEqual(f.severity, "HIGH")
        # URLs are shown in full (not high-entropy secrets to mask)
        self.assertEqual(f.evidence, fx.FIREBASE_DB)

    def test_generic_credential_detected(self):
        text = 'String token = "client_secret=Zx9Kq2mLn7Pw3Rt8Vb";'
        found = ids(secrets.scan_text(text, "x"))
        self.assertIn("SECRET_HARDCODED_CREDENTIAL", found)

    def test_placeholder_not_flagged(self):
        text = 'api_key="your_api_key_here"\npassword="changeme"\nsecret="xxxxxxxxxxxx"'
        found = ids(secrets.scan_text(text, "x"))
        self.assertNotIn("SECRET_HARDCODED_CREDENTIAL", found)

    def test_low_entropy_not_flagged(self):
        self.assertFalse(secrets._looks_secret("aaaaaaaaaaaaaaaa"))
        self.assertFalse(secrets._looks_secret("1234567890123"))
        self.assertTrue(secrets._looks_secret("Zx9Kq2mLn7Pw3Rt8Vb"))

    def test_no_false_positive_on_prose(self):
        text = "The quick brown fox jumps over the lazy dog. " * 20
        self.assertEqual(secrets.scan_text(text, "x"), [])

    def test_redaction_masks_middle(self):
        r = secrets.redact("AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(r.startswith("AKIA"))
        self.assertIn("...", r)
        self.assertNotIn("IOSFODNN7", r)

    def test_redaction_private_key(self):
        r = secrets.redact(fx.PRIVATE_KEY)
        self.assertIn("PRIVATE KEY", r)
        self.assertNotIn("MIIBOgIBAAJBAKj", r)

    def test_dedup_within_file(self):
        text = (fx.AWS_KEY + " ") * 5
        found = [f for f in secrets.scan_text(text, "x") if f.id == "SECRET_AWS_ACCESS_KEY_ID"]
        self.assertEqual(len(found), 1)


if __name__ == "__main__":
    unittest.main()
