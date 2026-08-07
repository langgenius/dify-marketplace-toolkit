"""Publishing entry point; the logic lives in the ``uploader`` package.

Both plugin repositories call this exact path from their pre-check and merge
workflows, so the file stays put as a thin stub — the same pattern as the
``validator/bin`` adapters. See ``uploader/cli.py``.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uploader.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
