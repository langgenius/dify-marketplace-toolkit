"""Shared, importable core for the Dify Marketplace toolkit.

Everything in this package is a module: underscore names, no ``sys.exit``, no
``argparse``. The CLI surface lives in ``validator/`` and is a thin shell over
these functions, which is what lets the same logic serve three consumers with
three different isolation strategies:

* ``validator/validate-difypkg.py`` runs each check as a subprocess, so one
  crashing check cannot take the other ten down and each gets its own timeout.
* ``uploader/upload-package.py`` imports :mod:`toolkit.scan` directly, because
  it wants one JSON object and its own fail-open wrapper.
* ``tests/`` imports the pure functions with no isolation at all, because a
  test that swallows the exception is not a test.

Isolation is a property of the consumer, not of the check.
"""
