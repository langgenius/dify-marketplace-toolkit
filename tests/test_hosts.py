"""Hostname extraction, and the subtraction that makes it useful.

The raw regex is trivial. What these tests defend is everything that gets
thrown away afterwards -- documentation links, reserved names, vendored
dependency trees, scraped address tables -- plus the honesty of the
``runtime_constructed`` counter, which is how the plugin page admits to the
hostnames a static scan cannot see.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from toolkit.scan import hosts


def write_plugin(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="plugin-scan-test-"))
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


class AccessDomainTest(unittest.TestCase):
    def hosts(self, files: dict[str, str]) -> list[str]:
        return hosts.extract_access_domains(write_plugin(files)).hosts()

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
        scan = hosts.extract_access_domains(
            write_plugin({"tool.py": 'HOST = "http://192.168.1.100:9000/api"\n'})
        )
        self.assertEqual([(d.host, d.kind) for d in scan.domains],
                         [("192.168.1.100", hosts.KIND_IP_PRIVATE)])

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
        scan = hosts.extract_access_domains(write_plugin(files))
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
        scan = hosts.extract_access_domains(write_plugin({"tool.py": source}))
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
            hosts.read_declared_domains(write_plugin({"manifest.yaml": manifest})),
            ["api.vendor.com", "*.cdn.vendor.com"],
        )

    def test_absent_node_yields_nothing(self):
        self.assertEqual(
            hosts.read_declared_domains(write_plugin({"manifest.yaml": "version: 0.1.0\n"})),
            [],
        )

    def test_a_pasted_url_is_reduced_to_its_host(self):
        manifest = "network:\n  domains:\n    - https://api.vendor.com/v1/chat\n    - API.Vendor.com\n"
        self.assertEqual(
            hosts.read_declared_domains(write_plugin({"manifest.yaml": manifest})),
            ["api.vendor.com"],
        )

    def test_wildcard_declaration_covers_subdomains(self):
        declared = ["*.vendor.com", "api.other.com"]
        self.assertEqual(
            hosts.undeclared_hosts(
                ["a.vendor.com", "vendor.com", "api.other.com", "evil.net"], declared
            ),
            ["evil.net"],
        )

    def test_declared_but_undetected_is_not_a_finding(self):
        """An SDK holds its own base URL; a declaration is how that gets known."""
        self.assertEqual(hosts.undeclared_hosts([], ["api.vendor.com"]), [])


if __name__ == "__main__":
    unittest.main()
