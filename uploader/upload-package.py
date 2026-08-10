"""Deprecated alias for ``python3 path/to/uploader``.

The plugin repositories' workflows still call this exact path; it forwards
to the same CLI and disappears once both of them invoke the package
directory instead.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uploader.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
