"""What the generic secret-assignment tier may and may not block.

The vendor-token tier is regex-shaped and self-evident; these tests defend the
generic tier's gates, because every one of them exists to kill a real
false-positive class: ``credentials.get(...)`` reads flagged as leaks
(langgenius/dify-plugins#2887), ``max_tokens: 4096`` counted as a credential,
and English-ish dotted strings blocking a release. The flip side is also
pinned: a literal token in code, an ``.env`` value, and a PEM header must
still block.
"""

from __future__ import annotations

import unittest

from toolkit.checks import secrets

# Shaped like real secret material: mixed-case alphanumeric, high entropy.
FAKE_TOKEN = "J8kQz3vN7pXw2RbT5mYc9DfH4LgSnAe6"
FAKE_HEX = "3f9a1c7e5b2d8460fa91c37e24b5d906"


def scan(rel_path: str, text: str) -> tuple[list[str], list[str]]:
    return secrets.scan_text(rel_path, text)


class ExpressionRhsTest(unittest.TestCase):
    """Code that reads a credential is not code that embeds one."""

    def test_credentials_get_is_not_a_leak(self):
        errors, warnings = scan(
            "models/rerank/rerank.py",
            'api_key_value = credentials.get("api_key")\n',
        )
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_attribute_and_call_chains_are_skipped_silently(self):
        source = (
            "token = self._config.auth_token\n"
            "num_tokens = self._get_num_tokens_by_gpt2(text)\n"
            "password = os.environ[ENV_NAME]\n"
        )
        errors, warnings = scan("provider/provider.py", source)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_unquoted_config_values_are_still_literals(self):
        errors, _ = scan("config/.env", f"API_KEY={FAKE_TOKEN}\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("API_KEY", errors[0])


class LiteralShapeTest(unittest.TestCase):
    def test_quoted_token_in_code_blocks(self):
        errors, _ = scan("tool.py", f'api_key = "{FAKE_TOKEN}"\n')
        self.assertEqual(len(errors), 1)

    def test_hex_literal_blocks_at_lower_entropy_floor(self):
        errors, _ = scan("settings.yaml", f"access_key: {FAKE_HEX}\n")
        self.assertEqual(len(errors), 1)

    def test_masking_never_echoes_the_secret(self):
        errors, _ = scan("tool.py", f'api_key = "{FAKE_TOKEN}"\n')
        self.assertNotIn(FAKE_TOKEN, errors[0])

    def test_dotted_identifier_string_warns_instead_of_blocking(self):
        """English-ish strings sit below the token entropy floor on purpose."""
        errors, warnings = scan("llm.py", 'token_key = "usage.total_tokens"\n')
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)

    def test_low_entropy_filler_warns_instead_of_blocking(self):
        errors, warnings = scan("conf.yaml", "api_key: aaaabbbbccccdddd\n")
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)


class NonSecretValueTest(unittest.TestCase):
    def test_counts_and_flags_are_dropped(self):
        source = "max_tokens: 4096\nstream_tokens: true\ntemperature_token: -1.5\n"
        errors, warnings = scan("model.yaml", source)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_placeholders_are_dropped(self):
        source = "api_key: <YOUR_API_KEY>\npassword: ${DB_PASSWORD}\nsecret: your-api-key\n"
        errors, warnings = scan("README.md", source)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])


class VendorTierTest(unittest.TestCase):
    """The self-identifying formats block regardless of context."""

    def test_openai_style_key_blocks_even_unassigned(self):
        errors, _ = scan("notes.txt", f"see sk-{FAKE_TOKEN} for testing\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("OpenAI-style API key", errors[0])

    def test_private_key_header_blocks(self):
        errors, _ = scan("cert.pem", "-----BEGIN RSA PRIVATE KEY-----\n")
        self.assertEqual(len(errors), 1)

    def test_vendor_match_suppresses_the_generic_pass(self):
        errors, _ = scan("conf.env", f"OPENAI_API_KEY=sk-{FAKE_TOKEN}\n")
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
