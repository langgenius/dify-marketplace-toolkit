"""Capability detection is a precision problem, not a recall problem.

Every test here pins a rule chosen from measuring the whole plugin corpus.
Matching SQL keywords in YAML once put the "SQL or database access" hit rate at
67% against a true 5.4%; these tests are what stop that from coming back.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from toolkit.scan import capabilities


def write_plugin(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="plugin-scan-test-"))
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


class CapabilityDetectionTest(unittest.TestCase):
    def categories(self, files: dict[str, str]) -> dict[str, int]:
        root = write_plugin(files)
        return {item.name: item.count for item in capabilities.scan_capabilities(root)}

    def test_network_delete_is_not_database_access(self):
        """``requests.delete(url)`` is a network call, not a DELETE statement.

        The old scanner matched a bare ``DELETE`` keyword case-insensitively
        and stopped at the first matching category, so this line was filed
        under SQL and its network signal vanished entirely.
        """
        counts = self.categories({"tool.py": "requests.delete(url, timeout=5)\n"})
        self.assertEqual(counts.get("arbitrary network requests"), 1)
        self.assertNotIn("SQL or database access", counts)

    def test_select_parameter_type_is_not_database_access(self):
        """A ``type: select`` form parameter is not a SQL query.

        This one rule put the measured "SQL or database access" hit rate at
        67% of all plugins against a true 5.4%.
        """
        counts = self.categories(
            {"tools/x.yaml": "parameters:\n  - name: mode\n    type: select\n"}
        )
        self.assertNotIn("SQL or database access", counts)

    def test_real_sql_is_still_detected(self):
        counts = self.categories(
            {"db.py": 'cursor.execute("SELECT id FROM users WHERE name = ?", (name,))\n'}
        )
        self.assertGreaterEqual(counts.get("SQL or database access", 0), 1)

    def test_regex_compile_is_not_code_execution(self):
        counts = self.categories({"tool.py": "import re\nPATTERN = re.compile(r'x')\n"})
        self.assertNotIn("code execution", counts)

    def test_builtin_compile_is_code_execution(self):
        counts = self.categories({"tool.py": "obj = compile(src, '<s>', 'exec')\n"})
        self.assertEqual(counts.get("code execution"), 1)

    def test_one_line_can_match_several_categories(self):
        counts = self.categories({"tool.py": "subprocess.run(open(path).read())\n"})
        self.assertEqual(counts.get("command execution"), 1)
        self.assertEqual(counts.get("filesystem operations"), 1)

    def test_count_is_not_capped_by_the_sample_limit(self):
        """The cap limits stored examples; the total stays true.

        The old cap stopped counting as well as collecting, so any plugin with
        more than 20 hits in a category under-reported without saying so.
        """
        body = "".join(f"requests.get(url_{index})\n" for index in range(50))
        root = write_plugin({"tool.py": body})
        categories = {item.name: item for item in capabilities.scan_capabilities(root)}
        network = categories["arbitrary network requests"]
        self.assertEqual(network.count, 50)
        self.assertEqual(len(network.samples), capabilities.MAX_SAMPLES_PER_CATEGORY)


if __name__ == "__main__":
    unittest.main()
