"""Tests for the threat catalogue, the icon machinery, and the web server."""
import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from apkinspect import catalog, scanner
from apkinspect.web.server import Handler
from tests import fixtures as fx
from tools import make_icon


class TestCatalog(unittest.TestCase):
    def test_payload_shape(self):
        p = catalog.as_payload()
        self.assertIn("threats", p)
        self.assertIn("severities", p)
        self.assertTrue(p["threats"])

    def test_ids_unique_and_valid_severity(self):
        seen = set()
        for t in catalog.THREATS:
            self.assertIn(t["severity"], catalog.SEVERITY_META)
            self.assertIn(t["category"], catalog.CATEGORY_META)
            for fid in t["ids"]:
                self.assertNotIn(fid, seen, f"duplicate id {fid}")
                seen.add(fid)
                for field in ("what", "risk", "detect", "block"):
                    self.assertTrue(t[field].strip(), f"{t['key']} missing {field}")

    def test_every_emitted_finding_has_an_entry(self):
        """Integrity: every finding the scanner can produce is explained in the book."""
        import os, tempfile
        data = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
        fd, path = tempfile.mkstemp(suffix=".apk")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            result = scanner.scan_file(path)
        finally:
            os.remove(path)
        for f in result.findings:
            self.assertIsNotNone(catalog.for_finding_id(f.id), f"no catalogue entry for {f.id}")


class TestIcon(unittest.TestCase):
    def test_png_header(self):
        png = make_icon.png_bytes(2, 2, bytes(2 * 2 * 4))
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        self.assertIn(b"IHDR", png[:32])
        self.assertTrue(png.endswith(b"IEND" + png[-4:]))

    def test_ico_header(self):
        png = make_icon.png_bytes(2, 2, bytes(16))
        ico = make_icon.ico_bytes([(16, png)])
        self.assertEqual(ico[:4], b"\x00\x00\x01\x00")  # reserved, type=1
        self.assertEqual(ico[4:6], b"\x01\x00")          # count = 1

    def test_downscale_averages(self):
        c = make_icon.Canvas(2, 2)
        for x in range(2):
            for y in range(2):
                c.set(x, y, (200, 100, 50), 255)
        out = make_icon.downscale(c, 1)
        self.assertEqual(out, bytes([200, 100, 50, 255]))


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()

    def test_index(self):
        status, ctype, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"APKInspect", body)

    def test_static_assets(self):
        for path, needle in (("/static/styles.css", b"--bg"),
                             ("/static/app.js", b"renderResults"),
                             ("/icon.svg", b"<svg")):
            status, _, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(needle, body, path)

    def test_catalog_api(self):
        status, ctype, body = self.get("/api/catalog")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["threats"])

    def test_path_traversal_blocked(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/static/../server.py")
        self.assertEqual(cm.exception.code, 404)

    def test_scan_endpoint(self):
        apk = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
        req = urllib.request.Request(self.base + "/api/scan", data=apk, method="POST",
                                     headers={"X-Filename": "vuln.apk"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        self.assertEqual(data["file_type"], "apk")
        self.assertEqual(data["path"], "vuln.apk")
        self.assertLess(data["score"], 50)
        ids = {f["id"] for f in data["findings"]}
        self.assertIn("SECRET_PRIVATE_KEY", ids)

    def test_demo_endpoint(self):
        import os, tempfile
        apk = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
        fd, path = tempfile.mkstemp(suffix=".apk")
        with os.fdopen(fd, "wb") as fh:
            fh.write(apk)
        os.environ["APKINSPECT_DEMO"] = path
        try:
            status, _, body = self.get("/api/demo")
            data = json.loads(body)
            self.assertEqual(status, 200)
            self.assertEqual(data["path"], "vulnerable-sample.apk")
            self.assertIn("score", data)
        finally:
            os.environ.pop("APKINSPECT_DEMO", None)
            os.remove(path)

    def test_scan_rejects_empty(self):
        req = urllib.request.Request(self.base + "/api/scan", data=b"", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
