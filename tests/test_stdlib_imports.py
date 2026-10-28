"""The runtime must stay standard-library only.

CI runs the suite in an environment with nothing installed, so an accidental `import openai` in a
*reachable* module would fail there. But a lazily-imported one (inside a function that the stub
tests never call) could slip through a green CI. This test closes that: it parses every module
under ``src/assay_bench`` and fails if any imports a package that is neither the standard library
nor this project. The LLM-agent adapter in particular talks to a model API over ``http.client`` for
exactly this reason -- so no SDK is ever a dependency.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
PKG = SRC / "assay_bench"

#: Local top-level names that are allowed (this project's own modules).
_LOCAL = {"assay_bench", "scoring", "assay_verifier", "badge"}
_STDLIB = set(sys.stdlib_module_names)


def _top(name: str) -> str:
    return name.split(".", 1)[0]


class StdlibOnly(unittest.TestCase):
    def test_no_third_party_imports_anywhere_under_the_package(self) -> None:
        offenders: list[str] = []
        for path in sorted(PKG.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [_top(a.name) for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:            # relative import -- always local
                        continue
                    names = [_top(node.module or "")]
                else:
                    continue
                for n in names:
                    if n and n not in _STDLIB and n not in _LOCAL:
                        offenders.append(f"{path.relative_to(SRC)}: {n}")
        self.assertEqual(offenders, [],
                         "third-party imports found in the stdlib-only runtime:\n"
                         + "\n".join(offenders))

    def test_the_guard_can_actually_see_a_violation(self) -> None:
        # A guard that never fires is worthless; prove it flags a planted third-party import.
        src = "import anthropic\nfrom openai import OpenAI\n"
        tree = ast.parse(src)
        found = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found += [_top(a.name) for a in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                found.append(_top(node.module or ""))
        bad = [n for n in found if n not in _STDLIB and n not in _LOCAL]
        self.assertEqual(sorted(bad), ["anthropic", "openai"])


if __name__ == "__main__":
    unittest.main()
