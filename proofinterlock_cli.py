"""Repository-root launcher for isolated Windows/Python runs.

``python -I`` implies safe-path mode and may omit both the current directory
and the script directory from ``sys.path``.  This launcher explicitly inserts
its own trusted, adjacent repository directory before importing the package.
It never inserts the caller's current working directory.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from proofinterlock.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
