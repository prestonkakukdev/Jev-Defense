#!/usr/bin/env python3
"""
Backwards-compatible entry point. All hook logic now lives in `jev_defense.hosts`, which
speaks Claude Code, Codex, Copilot CLI, Gemini CLI, and Cursor. New installs use
`jevdefense install <agent>`, which calls `python -m jev_defense hook` directly.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jev_defense.hosts import main  # noqa: E402

if __name__ == "__main__":
    main(sys.argv[1:])
