"""Make the package runnable: ``python3 path/to/uploader``.

Both plugin repositories copy this repository into ``.scripts`` and run the
uploader from there, so the path bootstrap cannot assume an installed
package.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uploader.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
