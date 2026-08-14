"""The source-host admission policy, and the error that points at it.

The list itself is data; what these tests defend is that both consumers keep
reading it (manifest whole-value form, README prose form), that an admitted
self-hosted forge actually passes, and that a rejection names the offending
host and the extension path instead of dead-ending the submitter.
"""

from __future__ import annotations

import unittest

from toolkit.checks import source_hosts
from toolkit.checks.source_hosts import (
    SOURCE_REPOSITORY_LINK_RE,
    SOURCE_REPOSITORY_URL_RE,
    unsupported_repo_error,
)


class UrlFormTest(unittest.TestCase):
    def test_every_allowed_host_passes_as_manifest_value(self):
        for host in source_hosts.ALLOWED_SOURCE_HOSTS:
            with self.subTest(host=host):
                self.assertTrue(SOURCE_REPOSITORY_URL_RE.search(f"https://{host}/org/repo"))

    def test_admitted_self_hosted_forge_passes(self):
        self.assertTrue(
            SOURCE_REPOSITORY_URL_RE.search(
                "https://gitlab.anchnet.com/anchnet_ai/anspire-llm-plugin"
            )
        )

    def test_unknown_host_fails(self):
        self.assertFalse(SOURCE_REPOSITORY_URL_RE.search("https://evil.example.com/org/repo"))

    def test_lookalike_host_suffix_fails(self):
        """`github.com.evil.tld` must not ride on the github.com entry."""
        self.assertFalse(SOURCE_REPOSITORY_URL_RE.search("https://github.com.evil.tld/org/repo"))

    def test_manifest_form_requires_the_whole_value_to_be_the_url(self):
        self.assertFalse(SOURCE_REPOSITORY_URL_RE.search("see https://github.com/org/repo"))


class LinkFormTest(unittest.TestCase):
    def test_url_is_found_inside_prose(self):
        readme = "## Source\n\nSource: https://gitlab.anchnet.com/anchnet_ai/anspire-llm-plugin\n"
        self.assertTrue(SOURCE_REPOSITORY_LINK_RE.search(readme))

    def test_unknown_host_in_prose_is_not_enough(self):
        self.assertFalse(SOURCE_REPOSITORY_LINK_RE.search("Source: https://code.internal.corp/x/y"))


class RejectionMessageTest(unittest.TestCase):
    def test_error_names_host_and_extension_path(self):
        message = unsupported_repo_error("https://code.internal.corp/org/repo")
        self.assertIn("code.internal.corp", message)
        self.assertIn("source_hosts.py", message)

    def test_unparseable_value_falls_back_to_raw_text(self):
        message = unsupported_repo_error("not a url")
        self.assertIn("not a url", message)


if __name__ == "__main__":
    unittest.main()
