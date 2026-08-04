"""Regression tests for the shared plugin scanner.

Run with ``python3 -m unittest discover -s validator -p 'test_*.py'``.

Every test here pins down a rule that was chosen from measurement over the
whole plugin corpus, and that silently produces wrong Marketplace data if it
regresses. They are cheap and offline: nothing here touches the network.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import plugin_scan


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
        return {item.name: item.count for item in plugin_scan.scan_capabilities(root)}

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
        categories = {item.name: item for item in plugin_scan.scan_capabilities(root)}
        network = categories["arbitrary network requests"]
        self.assertEqual(network.count, 50)
        self.assertEqual(len(network.samples), plugin_scan.MAX_SAMPLES_PER_CATEGORY)


class AccessDomainTest(unittest.TestCase):
    def hosts(self, files: dict[str, str]) -> list[str]:
        return plugin_scan.extract_access_domains(write_plugin(files)).hosts()

    def test_literal_host_in_code_is_detected(self):
        self.assertEqual(
            self.hosts({"tool.py": 'BASE = "https://api.example-vendor.com/v1"\n'}),
            ["api.example-vendor.com"],
        )

    def test_host_survives_a_call_split_across_lines(self):
        """A formatter wrapping the call must not hide the hostname.

        Line-by-line matching missed these, which meant even hard-coded
        domains could go unreported.
        """
        source = 'import requests\nrequests.get(\n    "https://api.vendor.io/v1/models",\n    timeout=5,\n)\n'
        self.assertEqual(self.hosts({"tool.py": source}), ["api.vendor.io"])

    def test_docstrings_and_comments_are_not_access(self):
        source = (
            '"""See https://docs-portal.vendor.io/reference for details."""\n'
            "VALUE = 1  # more at https://blog.vendor.io/post\n"
        )
        self.assertEqual(self.hosts({"tool.py": source}), [])

    def test_help_links_in_yaml_are_not_access(self):
        """"Where to get your API key" is a link for the human, not a request."""
        source = (
            "identity:\n  name: demo\n"
            "help:\n  url:\n    en_US: https://console.vendor.com/tokens\n"
            "credentials_for_provider:\n"
            "  api_key:\n    url: https://portal.vendor.com/keys\n"
            "  base_url:\n    default: https://api.vendor.com/v1\n"
        )
        self.assertEqual(self.hosts({"provider/demo.yaml": source}), ["api.vendor.com"])

    def test_source_hosting_and_reserved_names_are_excluded(self):
        source = (
            'A = "https://github.com/acme/plugin"\n'
            'B = "https://api.example.com/v1"\n'
            'C = "https://docs.vendor.com/guide"\n'
            'D = "http://127.0.0.1:8000/health"\n'
        )
        self.assertEqual(self.hosts({"tool.py": source}), [])

    def test_private_addresses_are_kept_and_classified(self):
        scan = plugin_scan.extract_access_domains(
            write_plugin({"tool.py": 'HOST = "http://192.168.1.100:9000/api"\n'})
        )
        self.assertEqual([(d.host, d.kind) for d in scan.domains],
                         [("192.168.1.100", plugin_scan.KIND_IP_PRIVATE)])

    def test_vendored_dependency_trees_are_skipped(self):
        """A shipped venv or vendor bundle describes its own hosts, not the plugin's.

        One package in the corpus yielded 4657 hostnames purely from a
        vendored data file and a bundled ``site-packages`` tree.
        """
        files = {
            "tool.py": 'BASE = "https://api.vendor.com"\n',
            ".venv312/lib/python3.12/site-packages/dep/client.py": 'X = "https://telemetry.dep.io"\n',
            "vendor/bundle.js": 'const u = "https://cdn.other.net/lib";\n',
        }
        self.assertEqual(self.hosts(files), ["api.vendor.com"])

    def test_data_payload_files_are_skipped(self):
        body = "\n".join(f'"row{index}": "https://host{index}.example-corp.com/"' for index in range(40))
        files = {"tool.py": 'BASE = "https://api.vendor.com"\n', "data/urls.json": "{" + body + "}"}
        scan = plugin_scan.extract_access_domains(write_plugin(files))
        self.assertEqual(scan.hosts(), ["api.vendor.com"])
        self.assertEqual(scan.skipped_data_files, 1)

    def test_runtime_constructed_calls_are_counted_not_guessed(self):
        """Most plugins build their URL at runtime; that has to be visible.

        Showing only extractable hosts reads as "this plugin contacts exactly
        these", which is false. Across the corpus 92% of outbound call sites
        assemble their address at runtime.
        """
        source = (
            "import requests\n"
            'requests.get(f"{self.base_url}/v1/models")\n'
            'requests.post("https://api.vendor.com/v1/chat", json=body)\n'
        )
        scan = plugin_scan.extract_access_domains(write_plugin({"tool.py": source}))
        self.assertEqual(scan.network_callsites, 2)
        self.assertEqual(scan.runtime_constructed, 1)
        self.assertEqual(scan.hosts(), ["api.vendor.com"])


class DeclaredDomainTest(unittest.TestCase):
    def test_reads_the_manifest_network_node(self):
        manifest = (
            "version: 0.1.0\n"
            "type: plugin\n"
            "network:\n"
            "  domains:\n"
            "    - api.vendor.com\n"
            '    - "*.cdn.vendor.com"\n'
            "resource:\n"
            "  memory: 1048576\n"
        )
        self.assertEqual(
            plugin_scan.read_declared_domains(write_plugin({"manifest.yaml": manifest})),
            ["api.vendor.com", "*.cdn.vendor.com"],
        )

    def test_absent_node_yields_nothing(self):
        self.assertEqual(
            plugin_scan.read_declared_domains(write_plugin({"manifest.yaml": "version: 0.1.0\n"})),
            [],
        )

    def test_a_pasted_url_is_reduced_to_its_host(self):
        manifest = "network:\n  domains:\n    - https://api.vendor.com/v1/chat\n    - API.Vendor.com\n"
        self.assertEqual(
            plugin_scan.read_declared_domains(write_plugin({"manifest.yaml": manifest})),
            ["api.vendor.com"],
        )

    def test_wildcard_declaration_covers_subdomains(self):
        declared = ["*.vendor.com", "api.other.com"]
        self.assertEqual(
            plugin_scan.undeclared_hosts(
                ["a.vendor.com", "vendor.com", "api.other.com", "evil.net"], declared
            ),
            ["evil.net"],
        )

    def test_declared_but_undetected_is_not_a_finding(self):
        """An SDK holds its own base URL; a declaration is how that gets known."""
        self.assertEqual(plugin_scan.undeclared_hosts([], ["api.vendor.com"]), [])


class DependencyCollectionTest(unittest.TestCase):
    def test_pinned_requirements_resolve(self):
        files = {"requirements.txt": "requests==2.31.0\nhttpx>=0.27\n# comment\n"}
        scan = plugin_scan.collect_dependencies(write_plugin(files))
        self.assertEqual(scan.source, "requirements.txt")
        self.assertEqual(scan.resolved, [{"name": "requests", "version": "2.31.0"}])
        self.assertEqual(scan.unresolved, [{"name": "httpx", "specifier": ">=0.27"}])

    def test_uv_lock_wins_over_requirements(self):
        """``uv.lock`` is a resolved transitive closure; prefer it when present.

        Every official plugin is uv-native and its ``requirements.txt`` is
        generated during packaging.
        """
        files = {
            "requirements.txt": "requests>=2.0\n",
            "uv.lock": '[[package]]\nname = "requests"\nversion = "2.32.3"\n',
        }
        scan = plugin_scan.collect_dependencies(write_plugin(files))
        self.assertEqual(scan.source, "uv.lock")
        self.assertEqual(scan.resolved, [{"name": "requests", "version": "2.32.3"}])

    def test_no_dependency_manifest_is_empty_not_an_error(self):
        scan = plugin_scan.collect_dependencies(write_plugin({"main.py": "x = 1\n"}))
        self.assertEqual(scan.source, "")
        self.assertEqual(scan.resolved, [])


class ReportTest(unittest.TestCase):
    def test_sections_carry_independent_status(self):
        """A failed lookup must not make the other sections look absent."""

        def failing_lookup(_dependencies):
            return [], "failed"

        root = write_plugin(
            {
                "tool.py": 'BASE = "https://api.vendor.com"\n',
                "requirements.txt": "requests==2.31.0\n",
            }
        )
        report = plugin_scan.build_security_report(
            root, scanned_at="2026-08-04T00:00:00Z", vulnerability_lookup=failing_lookup
        )
        self.assertEqual(report["access_domains"]["status"], "ok")
        self.assertEqual(report["dependencies"]["status"], "failed")
        self.assertEqual(report["capabilities"]["status"], "ok")

    def test_no_dependency_file_is_skipped_not_failed(self):
        root = write_plugin({"tool.py": "x = 1\n"})
        report = plugin_scan.build_security_report(
            root, scanned_at="2026-08-04T00:00:00Z", vulnerability_lookup=lambda _d: ([], "ok")
        )
        self.assertEqual(report["dependencies"]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
