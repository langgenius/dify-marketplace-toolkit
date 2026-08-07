"""Transport contract of the uploader: upload first, then submit the scan
report against the checksum the Marketplace returned.

The report must never be able to fail a publish — the package is live by the
time the report travels, and a red merge workflow invites a re-run that
uploads the package again. So a submission failure warns and returns, a 4xx
is never retried, and only 5xx/timeouts are. These tests pin that HTTP
conversation with a fake ``requests`` module; the scanner itself is pinned by
its own suite.
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

UPLOADER_PATH = Path(__file__).resolve().parents[1] / "uploader" / "upload-package.py"

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


def load_uploader(fake_requests):
    """Load the uploader script with the fake ``requests`` in its globals.

    CI runs these tests without requests installed, so the fake is injected
    into ``sys.modules`` for the duration of the import and removed after —
    the module keeps its own reference.
    """
    saved = sys.modules.get("requests")
    sys.modules["requests"] = fake_requests
    try:
        spec = importlib.util.spec_from_file_location("uploader_under_test", UPLOADER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if saved is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = saved
    return module


class UploaderTransportTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeRequests()
        self.uploader = load_uploader(self.fake)
        # The scanner has its own suite; these tests pin the transport, so the
        # scan is replaced with a canned payload.
        self.uploader.build_security_report = lambda package: {"scanner_version": "test"}
        self.sleeps = []
        patcher = mock.patch.object(self.uploader.time, "sleep", self.sleeps.append)
        patcher.start()
        self.addCleanup(patcher.stop)
        package = tempfile.NamedTemporaryFile(suffix=".difypkg", delete=False)
        package.write(b"not a real package")
        package.close()
        self.package = package.name
        self.addCleanup(Path(self.package).unlink)

    def publish(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.uploader.upload_package(self.package, "tok", "https://mp", False, "")
        return out.getvalue()

    def puts(self):
        return [call for call in self.fake.calls if call[0] == "put"]

    def test_upload_carries_no_security_report_field(self):
        """The form field the Marketplace no longer reads must be gone."""
        self.fake.post_queue = [FakeResponse(body=UPLOAD_OK)]
        self.fake.put_queue = [FakeResponse(body=REPORT_OK)]
        self.publish()
        method, _url, kwargs = self.fake.calls[0]
        self.assertEqual(method, "post")
        self.assertNotIn("security_report", kwargs["data"])
        self.assertIn("timeout", kwargs)

    def test_report_addresses_the_returned_checksum(self):
        self.fake.post_queue = [FakeResponse(body=UPLOAD_OK)]
        self.fake.put_queue = [FakeResponse(body=REPORT_OK)]
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
        self.fake.post_queue = [FakeResponse(body=UPLOAD_OK)]
        self.fake.put_queue = [self.fake.RequestException("timed out") for _ in range(3)]
        out = self.publish()  # must not raise
        self.assertEqual(len(self.puts()), 3)
        self.assertEqual(len(self.sleeps), 2)
        self.assertIn("::warning::", out)

    def test_4xx_is_not_retried(self):
        """A contract disagreement does not become agreement by repetition."""
        self.fake.post_queue = [FakeResponse(body=UPLOAD_OK)]
        self.fake.put_queue = [FakeResponse(status_code=400, body={"code": -1}, text="bad envelope")]
        out = self.publish()
        self.assertEqual(len(self.puts()), 1)
        self.assertIn("::warning::", out)

    def test_5xx_is_retried_until_success(self):
        self.fake.post_queue = [FakeResponse(body=UPLOAD_OK)]
        self.fake.put_queue = [
            FakeResponse(status_code=502, body={"code": -1}),
            FakeResponse(body=REPORT_OK),
        ]
        out = self.publish()
        self.assertEqual(len(self.puts()), 2)
        self.assertNotIn("::warning::", out)

    def test_missing_checksum_skips_submission_with_warning(self):
        """An unsigned artifact has no identity to report against."""
        self.fake.post_queue = [FakeResponse(body={"code": 0, "data": {"version": {"version": "0.0.1"}}})]
        out = self.publish()
        self.assertEqual(self.puts(), [])
        self.assertIn("::warning::", out)

    def test_scan_failure_skips_submission_but_not_publish(self):
        self.uploader.build_security_report = lambda package: None
        self.fake.post_queue = [FakeResponse(body=UPLOAD_OK)]
        out = self.publish()
        self.assertEqual(self.puts(), [])
        self.assertIn("::warning::", out)

    def test_upload_failure_raises_and_submits_nothing(self):
        """Publishing stays loud: only the report is best-effort."""
        self.fake.post_queue = [FakeResponse(status_code=500, body={"code": -1})]
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(Exception):
                self.uploader.upload_package(self.package, "tok", "https://mp", False, "")
        self.assertEqual(self.puts(), [])

    def test_testing_mode_only_scans(self):
        """A pre-check run shows the author the scan without any HTTP."""
        scanned = []
        self.uploader.TESTING = True
        self.uploader.build_security_report = lambda package: scanned.append(package) or {}
        self.publish()
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(scanned, [self.package])


if __name__ == "__main__":
    unittest.main()
