"""Allow ``python -m seto``."""

from __future__ import annotations

import sys

from seto.cli import main

if __name__ == "__main__":
    sys.exit(main())
