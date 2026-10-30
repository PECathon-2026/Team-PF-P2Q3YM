import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {"urllib.request", "http.client", "requests", "httpx", "socket"}


class NetworkImportTests(unittest.TestCase):
    def test_no_network_imports_outside_gate(self):
        violations = []
        for source in (ROOT / "privacylens").rglob("*.py"):
            if "gate" in source.relative_to(ROOT / "privacylens").parts:
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                    if node.module == "urllib": names.extend((node.module + "." + alias.name) for alias in node.names)
                else:
                    continue
                for name in names:
                    if name in FORBIDDEN:
                        violations.append(f"{source.relative_to(ROOT)} imports {name}")
        self.assertEqual(violations, [])


if __name__ == "__main__": unittest.main()
