"""Upload a packaged plugin: ``POST /api/v1/plugins/inner-upload``.

This is the one call in the publish flow that must be loud: a failed publish
raises. The scan report is the opposite by contract — see ``scan_report``.
"""

from __future__ import annotations

import requests

# (connect, read). The read timeout is generous because packages can be large.
UPLOAD_TIMEOUT = (5, 300)


def upload(package: str, token: str, base_url: str, force: bool, changelog: str, allow_category_change: bool = False) -> str:
    """Upload the package; return the checksum Marketplace assigned to it.

    The checksum comes from the response because the signed artifact is
    rebuilt server-side — the local bytes cannot predict it. An empty return
    means the artifact was not signed, so there is no identity to submit a
    scan report against.
    """
    url = f"{base_url}/api/v1/plugins/inner-upload"

    payload = {
        "changelog": changelog,
        "forcely": 'true' if force else 'false',
    }
    # Sent only on opt-in, so a backend that predates the field never sees it.
    if allow_category_change:
        payload["allow_category_change"] = 'true'

    headers = {
        "Authorization": f"Bearer {token}"
    }

    with open(package, "rb") as handle:
        files = [
            ("file", (package, handle, "application/octet-stream"))
        ]
        resp = requests.post(url, headers=headers, data=payload, files=files, timeout=UPLOAD_TIMEOUT)
    body = resp.json()
    print(body)
    if resp.status_code != 200 or body.get("code") != 0:
        raise Exception(f"Failed to upload package: {body}")

    version = (body.get("data") or {}).get("version") or {}
    return str(version.get("checksum") or "")
