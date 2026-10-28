"""The booth page must be self-contained and its in-browser checks must match the Python verifier.

The booth recomputes HMAC digests, the raw-secret commitment and the fixed-denominator score in the
browser so a visitor can verify a result offline. That claim is only worth anything if the browser
math equals ``canary`` / ``assay_verifier``. This test builds the page from the committed Arsenal
data and asserts: (1) it is self-contained (no external script/style/font fetch); (2) the forge
seed's fired canary recomputes in Python exactly as the page's JS will; (3) the recompute fixture,
if present, recomputes. The JS and Python share the same four frozen `forms`, so Python parity is
the guarantee the page needs.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from assay_bench import canary as C                      # noqa: E402

ARSENAL = ROOT / "demo" / "arsenal"


def _build(tmp: Path) -> str:
    sys.path.insert(0, str(ROOT / "demo"))
    import build_booth
    out = tmp / "booth.html"
    build_booth.build(str(ARSENAL / "spectrum"), str(out))
    return out.read_text(encoding="utf-8")


class Booth(unittest.TestCase):
    def setUp(self):
        if not ARSENAL.exists():
            self.skipTest("no committed Arsenal data (demo/arsenal absent, e.g. in an sdist)")

    def test_page_is_self_contained(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            html = _build(Path(d))
        self.assertNotIn('src="http', html)
        self.assertNotIn("@import", html)
        self.assertNotIn("cdn.", html)
        self.assertNotIn("fonts.googleapis", html)
        self.assertIn('<script id="assay-data"', html)

    def test_forge_seed_canary_recomputes_in_python(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            html = _build(Path(d))
        data = json.loads(re.search(r'<script id="assay-data"[^>]*>(.*?)</script>', html, re.S).group(1))
        forge = data["forge"]
        secret = forge["run_secret_reveal"]
        # The commitment the page checks must bind the secret (raw-bytes SHA-256).
        self.assertEqual(C.commitment(secret), forge["run_secret_commitment"])
        fired = [f for f in forge["findings"] if f.get("fired") and f.get("canary")]
        self.assertTrue(fired, "the forge seed must carry at least one fired canary to challenge")
        for f in fired:
            c = f["canary"]
            d = C.digest(secret, C.preimage(c["origin"], c["tool"], c["step"]))
            self.assertTrue(C.detects(d, c["observed"]),
                            f"forge seed finding {f['id']} does not recompute; the booth's live "
                            f"check would wrongly reject a genuine result")

    def test_recompute_fixture_if_present(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            html = _build(Path(d))
        data = json.loads(re.search(r'<script id="assay-data"[^>]*>(.*?)</script>', html, re.S).group(1))
        rc = data.get("leak_proof")
        if not rc:
            self.skipTest("no leak proof attached (no model leaked in the committed spectrum)")
        d_ = C.digest(rc["run_secret_reveal"], C.preimage(rc["origin"], rc["tool"], rc["step"]))
        self.assertTrue(C.detects(d_, rc["observed"]),
                        "the recompute panel's fixture does not recompute in Python")


if __name__ == "__main__":
    unittest.main()
