"""Manifest security analysis."""
import unittest

from apkinspect import axml
from apkinspect.manifest import analyze, as_bool, as_int, protection_name
from tests import fixtures as fx


def analyze_tree(tree):
    root = axml.parse(fx.encode_axml(tree))
    return analyze(root)


def ids(findings):
    return [f.id for f in findings]


class TestCoercion(unittest.TestCase):
    def test_as_bool(self):
        self.assertIs(as_bool(True), True)
        self.assertIs(as_bool("true"), True)
        self.assertIs(as_bool("false"), False)
        self.assertIs(as_bool(1), True)
        self.assertIsNone(as_bool("@0x7f01"))

    def test_as_int(self):
        self.assertEqual(as_int(19), 19)
        self.assertEqual(as_int("26"), 26)
        self.assertIsNone(as_int("abc"))

    def test_protection_name(self):
        self.assertEqual(protection_name("signature"), "signature")
        self.assertEqual(protection_name(2), "signature")
        self.assertEqual(protection_name(0), "normal")
        self.assertEqual(protection_name("signature|privileged"), "signature")


class TestVulnerableManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.meta, cls.findings = analyze_tree(fx.vulnerable_manifest())
        cls.ids = ids(cls.findings)

    def test_metadata(self):
        self.assertEqual(self.meta["package"], "com.apkinspect.vulnerable")
        self.assertEqual(self.meta["min_sdk"], 19)
        self.assertEqual(self.meta["target_sdk"], 26)

    def test_debuggable(self):
        self.assertIn("MANIFEST_DEBUGGABLE", self.ids)

    def test_allowbackup_and_cleartext(self):
        self.assertIn("MANIFEST_ALLOWBACKUP", self.ids)
        self.assertIn("MANIFEST_CLEARTEXT", self.ids)

    def test_http_deeplink(self):
        self.assertIn("COMPONENT_HTTP_DEEPLINK", self.ids)

    def test_exported_provider_high(self):
        prov = [f for f in self.findings if f.id == "COMPONENT_EXPORTED" and "provider" in f.location]
        self.assertTrue(prov)
        self.assertEqual(prov[0].severity, "HIGH")

    def test_provider_grant_uri(self):
        self.assertIn("COMPONENT_PROVIDER_GRANTURI", self.ids)

    def test_implicit_exported_activity(self):
        # ImplicitActivity has a custom intent-filter but no exported flag
        exp = [f for f in self.findings if f.id == "COMPONENT_EXPORTED" and "ImplicitActivity" in f.location]
        self.assertTrue(exp)

    def test_dangerous_permissions(self):
        perms = [f for f in self.findings if f.id == "PERMISSION_DANGEROUS"]
        titles = " ".join(f.title for f in perms)
        self.assertIn("READ_SMS", titles)
        self.assertIn("SYSTEM_ALERT_WINDOW", titles)
        # SYSTEM_ALERT_WINDOW / REQUEST_INSTALL_PACKAGES are HIGH
        self.assertTrue(any(f.severity == "HIGH" for f in perms))

    def test_old_minsdk(self):
        self.assertIn("MANIFEST_OLD_MINSDK", self.ids)


class TestPermissionGuardedComponents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = fx.E("manifest", [fx.A("package", "com.x", ns=None)], [
            fx.E("permission", [fx.A("name", "com.x.SIG"), fx.A("protectionLevel", 2)]),
            fx.E("permission", [fx.A("name", "com.x.NORM"), fx.A("protectionLevel", 0)]),
            fx.E("application", [], [
                fx.E("service", [fx.A("name", ".SigService"), fx.A("exported", True),
                                 fx.A("permission", "com.x.SIG")]),
                fx.E("service", [fx.A("name", ".NormService"), fx.A("exported", True),
                                 fx.A("permission", "com.x.NORM")]),
                fx.E("service", [fx.A("name", ".ExtService"), fx.A("exported", True),
                                 fx.A("permission", "com.other.PERM")]),
            ]),
        ])
        _, cls.findings = analyze_tree(tree)

    def _by_location(self, needle):
        return [f for f in self.findings if needle in f.location]

    def test_signature_protected_is_silent(self):
        self.assertEqual(self._by_location("SigService"), [])

    def test_weak_permission_flagged(self):
        f = self._by_location("NormService")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].id, "COMPONENT_EXPORTED_WEAKPERM")

    def test_external_permission_noted(self):
        f = self._by_location("ExtService")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].id, "COMPONENT_EXPORTED_PERM")


class TestCleanManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.meta, cls.findings = analyze_tree(fx.clean_manifest())
        cls.ids = ids(cls.findings)

    def test_no_findings(self):
        self.assertEqual(self.findings, [], f"unexpected: {self.ids}")

    def test_launcher_not_flagged(self):
        self.assertNotIn("COMPONENT_EXPORTED", self.ids)


if __name__ == "__main__":
    unittest.main()
