"""Validate the binary-XML parser by round-tripping the encoder against it."""
import unittest

from apkinspect import axml
from tests import fixtures as fx


class TestAXMLRoundTrip(unittest.TestCase):
    def setUp(self):
        self.root = axml.parse(fx.encode_axml(fx.vulnerable_manifest()))

    def test_root_and_package(self):
        self.assertEqual(self.root.tag, "manifest")
        self.assertEqual(self.root.get("package", android=False), "com.apkinspect.vulnerable")

    def test_uses_sdk_ints(self):
        uses_sdk = next(iter(self.root.findall("uses-sdk")))
        self.assertEqual(uses_sdk.get("minSdkVersion"), 19)
        self.assertEqual(uses_sdk.get("targetSdkVersion"), 26)

    def test_boolean_attribute(self):
        app = next(iter(self.root.findall("application")))
        val = app.get("debuggable")
        self.assertIsInstance(val, bool)
        self.assertTrue(val)

    def test_namespace_resolved(self):
        app = next(iter(self.root.findall("application")))
        attr = app.attr("debuggable")
        self.assertTrue(attr.is_android)
        self.assertEqual(attr.ns, axml.ANDROID_NS)

    def test_permissions_present(self):
        names = {p.get("name") for p in self.root.findall("uses-permission")}
        self.assertIn("android.permission.READ_SMS", names)
        self.assertIn("android.permission.SYSTEM_ALERT_WINDOW", names)

    def test_nested_intent_filter(self):
        activities = self.root.findall("activity")
        self.assertTrue(activities)
        # the public activity should carry a BROWSABLE category with http data
        schemes = []
        for act in activities:
            for flt in act.children:
                if flt.tag == "intent-filter":
                    for data in flt.children:
                        if data.tag == "data" and data.get("scheme"):
                            schemes.append(data.get("scheme"))
        self.assertIn("http", schemes)

    def test_string_values_decoded(self):
        provider = next(iter(self.root.findall("provider")))
        self.assertEqual(provider.get("authorities"), "com.apkinspect.vulnerable.provider")

    def test_rejects_non_axml(self):
        with self.assertRaises(axml.AXMLError):
            axml.parse(b"not a binary xml file at all")


if __name__ == "__main__":
    unittest.main()
