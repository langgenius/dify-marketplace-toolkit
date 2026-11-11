"""The dependency policy: what a plugin is allowed to install at runtime.

These tests pin the ``dify-plugin`` floor and the version-constraint grading,
because both are decisions rather than mechanics: the floor is the line the
marketplace has moved to, and the graded constraints are what a reviewer reads
when a submission is held. A floor that silently drifts, or a message that
disagrees with the rule it reports, would send authors chasing the wrong fix.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from toolkit.checks import dependencies


def write_plugin(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="dep-policy-test-"))
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def check(requirements: str) -> tuple[list[str], list[str]]:
    return dependencies.validate_dependencies(write_plugin({"requirements.txt": requirements}))


class DifyPluginFloorTest(unittest.TestCase):
    def test_current_line_is_accepted(self):
        for requirement in ("dify-plugin>=0.10.0", "dify-plugin==0.10.2"):
            with self.subTest(requirement=requirement):
                errors, _ = check(requirement + "\n")
                self.assertEqual([e for e in errors if "dify_plugin" in e], [])

    def test_newer_than_the_floor_is_accepted(self):
        errors, _ = check("dify-plugin>=0.11.0\n")
        self.assertEqual([e for e in errors if "dify_plugin" in e], [])

    def test_previous_generation_is_rejected(self):
        for requirement in ("dify-plugin>=0.9.0", "dify-plugin==0.9.1", "dify-plugin>=0.9.0,<0.10.0"):
            with self.subTest(requirement=requirement):
                errors, _ = check(requirement + "\n")
                self.assertTrue(
                    any("dify_plugin dependency must be >= 0.10.0" in e for e in errors),
                    f"{requirement} should be blocked: {errors}",
                )

    def test_message_is_derived_from_the_constant(self):
        # The rule and the sentence reporting it must not drift apart.
        errors, _ = check("dify-plugin>=0.9.0\n")
        self.assertIn(f"must be >= {dependencies.MIN_DIFY_PLUGIN_TEXT}", errors[0])

    def test_compatible_release_constraint_is_read_as_a_lower_bound(self):
        # ``~=0.10.0`` pins the 0.10 line; only >= and == used to be understood,
        # which rejected it with a misleading "no lower bound" error.
        errors, _ = check("dify-plugin~=0.10.0\n")
        self.assertEqual([e for e in errors if "dify_plugin" in e], [])

    def test_two_component_floor_compares_equal_to_three(self):
        errors, _ = check("dify-plugin>=0.10\n")
        self.assertEqual([e for e in errors if "dify_plugin" in e], [])

    def test_unconstrained_dify_plugin_is_rejected(self):
        errors, _ = check("dify-plugin\n")
        self.assertTrue(any("dify_plugin dependency must be >= 0.10.0" in e for e in errors))


class VersionConstraintGradingTest(unittest.TestCase):
    def test_no_constraint_blocks(self):
        errors, _ = check("requests\n")
        self.assertTrue(any("has no version constraint" in e for e in errors))

    def test_lower_bound_only_warns(self):
        errors, warnings = check("requests>=2.31.0\n")
        self.assertEqual(errors, [])
        self.assertTrue(any("lower-bound" in w for w in warnings))

    def test_bounded_range_is_clean(self):
        errors, warnings = check("requests>=2.31.0,<3\n")
        self.assertEqual(errors, [])
        self.assertEqual([w for w in warnings if "requests" in w], [])

    def test_git_and_direct_url_installs_block(self):
        for requirement in ("requests @ git+https://github.com/psf/requests.git",
                            "requests @ https://example.com/requests.whl"):
            with self.subTest(requirement=requirement):
                errors, _ = check(requirement + "\n")
                self.assertTrue(errors, f"{requirement} should block")

    def test_pyproject_dependencies_are_checked_too(self):
        root = write_plugin({
            "pyproject.toml": '[project]\ndependencies = ["dify-plugin>=0.9.0", "requests"]\n'
        })
        errors, _ = dependencies.validate_dependencies(root)
        self.assertTrue(any("dify_plugin dependency must be >= 0.10.0" in e for e in errors))
        self.assertTrue(any("requests" in e and "no version constraint" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
