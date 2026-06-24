"""APK signing analysis: certificate parsing and finding generation."""
import os
import tempfile
import unittest

from apkinspect import signing
from apkinspect.scanner import scan_file
from tests import fixtures as fx


def write_tmp(data: bytes, suffix: str = ".apk") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


class TestCertParsing(unittest.TestCase):
    def test_debug_sha1_2048(self):
        cert = signing.parse_certificate(
            fx.build_certificate("Android Debug", fx.SHA1_RSA_OID, 2048))
        self.assertTrue(cert.is_debug)
        self.assertTrue(cert.weak_sig_algo)
        self.assertEqual(cert.sig_algo, "SHA1withRSA")
        self.assertEqual(cert.key_bits, 2048)

    def test_release_sha256_1024(self):
        cert = signing.parse_certificate(
            fx.build_certificate("Acme Release Co", fx.SHA256_RSA_OID, 1024))
        self.assertFalse(cert.is_debug)
        self.assertFalse(cert.weak_sig_algo)
        self.assertEqual(cert.key_bits, 1024)

    def test_pkcs7_extracts_cert(self):
        cert = fx.build_certificate()
        certs = signing.certs_from_pkcs7(fx.build_pkcs7(cert))
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0], cert)


class TestSigningAnalysis(unittest.TestCase):
    def scan(self, **kw):
        data = fx.build_apk_bytes(fx.clean_manifest(), fx.clean_dex(), fx.signed_meta_inf(**kw))
        path = write_tmp(data)
        try:
            return {f.id for f in scan_file(path).findings}
        finally:
            os.remove(path)

    def test_debug_weak_short_v1(self):
        ids = self.scan(debug=True, weak=True, key_bits=1024)
        self.assertIn("SIGNING_DEBUG_CERT", ids)
        self.assertIn("SIGNING_WEAK_ALGORITHM", ids)
        self.assertIn("SIGNING_SHORT_KEY", ids)
        self.assertIn("SIGNING_V1_ONLY", ids)

    def test_release_cert_only_v1_only(self):
        ids = self.scan(debug=False, weak=False, key_bits=2048)
        self.assertNotIn("SIGNING_DEBUG_CERT", ids)
        self.assertNotIn("SIGNING_WEAK_ALGORITHM", ids)
        self.assertNotIn("SIGNING_SHORT_KEY", ids)
        self.assertIn("SIGNING_V1_ONLY", ids)   # no v2/v3 block in a plain zip

    def test_unsigned_apk_has_no_signing_findings(self):
        data = fx.build_apk_bytes(fx.clean_manifest(), fx.clean_dex())
        path = write_tmp(data)
        try:
            result = scan_file(path)
        finally:
            os.remove(path)
        self.assertFalse(any(f.category == "signing" for f in result.findings))

    def test_aab_skips_signing(self):
        data = fx.build_aab_bytes(fx.clean_dex())
        path = write_tmp(data, ".aab")
        try:
            result = scan_file(path)
        finally:
            os.remove(path)
        self.assertFalse(any(f.category == "signing" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
