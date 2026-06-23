"""Generate sample APK/AAB files (with deliberately planted issues) for demos
and manual testing. These are synthetic archives, not installable apps.

    python tools/make_samples.py [output_dir]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import fixtures as fx  # noqa: E402


def main(out_dir: str = "samples") -> None:
    os.makedirs(out_dir, exist_ok=True)

    vuln = fx.build_apk_bytes(fx.vulnerable_manifest(), fx.planted_dex(), fx.vulnerable_assets())
    clean = fx.build_apk_bytes(fx.clean_manifest(), fx.clean_dex())
    aab = fx.build_aab_bytes(fx.planted_dex(), fx.vulnerable_assets())

    for name, data in (("vulnerable.apk", vuln), ("clean.apk", clean), ("vulnerable.aab", aab)):
        path = os.path.join(out_dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"wrote {path} ({len(data)} bytes)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
