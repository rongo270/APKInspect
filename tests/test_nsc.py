"""Network Security Config parsing and findings."""
import io
import os
import tempfile
import unittest
import zipfile

from apkinspect import nsc
from apkinspect.scanner import scan_file
from tests import fixtures as fx


def _zip(entries: dict) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return zipfile.ZipFile(buf)


class TestNsc(unittest.TestCase):
    def test_flags_cleartext_and_user_ca(self):
        with _zip({fx.NSC_ENTRY: fx.nsc_axml()}) as zf:
            ids = {f.id for f in nsc.analyze(zf)}
        self.assertEqual(ids, {"NETWORK_NSC_CLEARTEXT", "NETWORK_NSC_USER_CA"})

    def test_no_nsc_no_findings(self):
        with _zip({"res/xml/other.xml": b"not a binary xml"}) as zf:
            self.assertEqual(nsc.analyze(zf), [])

    def test_end_to_end_in_scanner(self):
        data = fx.build_apk_bytes(fx.clean_manifest(), fx.clean_dex(), {fx.NSC_ENTRY: fx.nsc_axml()})
        fd, path = tempfile.mkstemp(suffix=".apk")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            ids = {f.id for f in scan_file(path).findings}
        finally:
            os.remove(path)
        self.assertIn("NETWORK_NSC_CLEARTEXT", ids)
        self.assertIn("NETWORK_NSC_USER_CA", ids)


if __name__ == "__main__":
    unittest.main()
