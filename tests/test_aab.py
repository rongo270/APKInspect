"""AAB protobuf manifest decoding."""
import unittest

from apkinspect import aab
from apkinspect.manifest import analyze
from tests import fixtures as fx


class TestAABManifest(unittest.TestCase):
    def setUp(self):
        self.root = aab.parse(fx.build_aab_manifest())

    def test_structure(self):
        self.assertEqual(self.root.tag, "manifest")
        self.assertEqual(self.root.get("package", android=False), "com.apkinspect.aab")

    def test_permission_string_value(self):
        names = {p.get("name") for p in self.root.findall("uses-permission")}
        self.assertIn("android.permission.READ_SMS", names)

    def test_compiled_boolean(self):
        app = next(iter(self.root.findall("application")))
        self.assertIs(app.get("debuggable"), True)

    def test_string_bool_value(self):
        act = next(iter(self.root.findall("activity")))
        self.assertEqual(act.get("exported"), "true")

    def test_analysis(self):
        meta, findings = analyze(self.root, is_aab=True)
        ids = {f.id for f in findings}
        self.assertIn("MANIFEST_DEBUGGABLE", ids)
        self.assertIn("COMPONENT_EXPORTED", ids)
        self.assertIn("PERMISSION_DANGEROUS", ids)

    def test_generic_protobuf_decoder(self):
        # sanity: nested message decoded
        from tests.fixtures import _pb_len, _pb_str
        payload = _pb_len(1, _pb_str(3, "hello"))
        fields = aab.parse_fields(payload)
        inner = aab.parse_fields(fields[1][0][1])
        self.assertEqual(inner[3][0][1], b"hello")


if __name__ == "__main__":
    unittest.main()
