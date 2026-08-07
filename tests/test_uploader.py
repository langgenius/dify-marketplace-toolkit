"""Transport contract of the uploader: upload first, then submit the scan
report against the checksum the Marketplace returned.

The report must never be able to fail a publish — the package is live by the
time the report travels, and a red merge workflow invites a re-run that
uploads the package again. So a submission failure warns and returns, a 4xx
is never retried, and only 5xx/timeouts are. These tests pin that HTTP
conversation with a fake ``requests`` module; the scanner itself is pinned by
its own suite.

The fake is registered in ``sys.modules`` before the ``uploader`` package is
first imported — its modules bind the name at import time — and removed
right after, which also keeps this suite runnable on the bare CI interpreter
where requests is not installed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

UPLOAD_OK = {"code": 0, "data": {"version": {"version": "0.0.1", "checksum": "abc123"}}}
REPORT_OK = {"code": 0, "data": {"projected": True, "duplicate": False}}


class FakeResponse:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body if body is not None else {"code": 0, "data": {}}
        self.text = text

    def json(self):
        return self._body


class FakeRequests(types.ModuleType):
    """Just enough of ``requests`` to record the uploader's HTTP calls.

    Queue a ``FakeResponse`` to return it, or an exception instance to raise
    it — that is how a timeout or connection error is simulated.
    """

    def __init__(self):
        super().__init__("requests")
        self.RequestException = type("RequestException", (IOError,), {})
        self.reset()

    def reset(self):
        self.calls = []
        self.post_queue = []
        self.put_queue = []

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return self._next(self.post_queue)

    def put(self, url, **kwargs):
        self.calls.append(("put", url, kwargs))
        return self._next(self.put_queue)

    @staticmethod
    def _next(queue):
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


FAKE = FakeRequests()

_saved = sys.modules.get("requests")
sys.modules["requests"] = FAKE
try:
    from uploader import cli, package_upload, scan_report  # noqa: E402
finally:
    if _saved is None:
        sys.modules.pop("requests", None)
    else:
        sys.modules["requests"] = _saved

assert package_upload.requests is FAKE and scan_report.requests is FAKE


class UploaderTransportTest(unittest.TestCase):
    def setUp(self):
        FAKE.reset()
        # The scanner has its own suite; these tests pin the transport, so the
        # scan is replaced with a canned payload.
        patcher = mock.patch.object(scan_report, "build", lambda package, scan_vulnerabilities=True: {"scanner_version": "test"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sleeps = []
        sleep_patcher = mock.patch.object(scan_report.time, "sleep", self.sleeps.append)
        sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)
        package = tempfile.NamedTemporaryFile(suffix=".difypkg", delete=False)
        package.write(b"not a real package")
        package.close()
        self.package = package.name
        self.addCleanup(Path(self.package).unlink)

    def options(self, **overrides):
        base = dict(
            token="tok",
            base_url="https://mp",
            force=False,
            changelog="",
            testing=False,
            scan_vulnerabilities=True,
            plugin_daemon_path="./dify-plugin",
        )
        base.update(overrides)
        return cli.Options(**base)

    def publish(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.publish_package(self.package, self.options(**overrides))
        return out.getvalue()

    def puts(self):
        return [call for call in FAKE.calls if call[0] == "put"]

    def test_upload_carries_no_security_report_field(self):
        """The form field the Marketplace no longer reads must be gone."""
        FAKE.post_queue = [FakeResponse(body=UPLOAD_OK)]
        FAKE.put_queue = [FakeResponse(body=REPORT_OK)]
        self.publish()
        method, _url, kwargs = FAKE.calls[0]
        self.assertEqual(method, "post")
        self.assertNotIn("security_report", kwargs["data"])
        self.assertIn("timeout", kwargs)

    def test_report_addresses_the_returned_checksum(self):
        FAKE.post_queue = [FakeResponse(body=UPLOAD_OK)]
        FAKE.put_queue = [FakeResponse(body=REPORT_OK)]
        out = self.publish()
        (_method, url, kwargs), = self.puts()
        self.assertTrue(url.endswith("/api/v1/plugin-artifacts/abc123/scan-report"), url)
        body = kwargs["json"]
        self.assertEqual(body["schema_version"], 1)
        self.assertTrue(body["producer"])
        self.assertIn("produced_at", body)
        self.assertEqual(body["scanner_version"], "test")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertIn("timeout", kwargs)
        self.assertNotIn("::warning::", out)

    def test_submission_failure_cannot_fail_the_publish(self):
        FAKE.post_queue = [FakeResponse(body=UPLOAD_OK)]
        FAKE.put_queue = [FAKE.RequestException("timed out") for _ in range(3)]
        out = self.publish()  # must not raise
        self.assertEqual(len(self.puts()), 3)
        self.assertEqual(len(self.sleeps), 2)
        self.assertIn("::warning::", out)

    def test_4xx_is_not_retried(self):
        """A contract disagreement does not become agreement by repetition."""
        FAKE.post_queue = [FakeResponse(body=UPLOAD_OK)]
        FAKE.put_queue = [FakeResponse(status_code=400, body={"code": -1}, text="bad envelope")]
        out = self.publish()
        self.assertEqual(len(self.puts()), 1)
        self.assertIn("::warning::", out)

    def test_5xx_is_retried_until_success(self):
        FAKE.post_queue = [FakeResponse(body=UPLOAD_OK)]
        FAKE.put_queue = [
            FakeResponse(status_code=502, body={"code": -1}),
            FakeResponse(body=REPORT_OK),
        ]
        out = self.publish()
        self.assertEqual(len(self.puts()), 2)
        self.assertNotIn("::warning::", out)

    def test_missing_checksum_skips_submission_with_warning(self):
        """An unsigned artifact has no identity to report against."""
        FAKE.post_queue = [FakeResponse(body={"code": 0, "data": {"version": {"version": "0.0.1"}}})]
        out = self.publish()
        self.assertEqual(self.puts(), [])
        self.assertIn("::warning::", out)

    def test_scan_failure_skips_submission_but_not_publish(self):
        with mock.patch.object(scan_report, "build", lambda package, scan_vulnerabilities=True: None):
            FAKE.post_queue = [FakeResponse(body=UPLOAD_OK)]
            out = self.publish()
        self.assertEqual(self.puts(), [])
        self.assertIn("::warning::", out)

    def test_upload_failure_raises_and_submits_nothing(self):
        """Publishing stays loud: only the report is best-effort."""
        FAKE.post_queue = [FakeResponse(status_code=500, body={"code": -1})]
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(Exception):
                cli.publish_package(self.package, self.options())
        self.assertEqual(self.puts(), [])

    def test_testing_mode_only_scans(self):
        """A pre-check run shows the author the scan without any HTTP."""
        scanned = []
        with mock.patch.object(scan_report, "build", lambda package, scan_vulnerabilities=True: scanned.append(package) or {}):
            self.publish(testing=True)
        self.assertEqual(FAKE.calls, [])
        self.assertEqual(scanned, [self.package])

    def test_cli_flags_reach_the_options(self):
        """The workflow-facing flags stay wired to the behaviour they name."""
        captured = {}
        argv = ["uploader", "-p", self.package, "-t", "tok", "-u", "https://mp", "-f", "--test", "--no-vuln-scan"]
        with mock.patch.object(cli, "publish_package", lambda pkg, opts: captured.update(package=pkg, options=opts)):
            with mock.patch.object(sys, "argv", argv):
                with contextlib.redirect_stdout(io.StringIO()):
                    cli.main()
        options = captured["options"]
        self.assertEqual(captured["package"], self.package)
        self.assertTrue(options.testing)
        self.assertFalse(options.scan_vulnerabilities)
        self.assertTrue(options.force)
        self.assertEqual(options.base_url, "https://mp")

    def test_entry_points_wire_the_cli(self):
        """`python3 .scripts/uploader` is the canonical invocation; the old
        `upload-package.py` path stays as an alias until both plugin
        repositories migrate. Each must reach the same CLI."""
        for entry in ("__main__.py", "upload-package.py"):
            with self.subTest(entry=entry):
                path = Path(__file__).resolve().parents[1] / "uploader" / entry
                spec = importlib.util.spec_from_file_location("uploader_entry_probe", path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.assertIs(module.main, cli.main)


if __name__ == "__main__":
    unittest.main()
