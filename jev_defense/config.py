"""
Where settings come from.

The API key can live in four places, checked in this order (first hit wins):

  1. TYPESAFE_API_KEY or JEV_API_KEY in the environment   (CLIs inherit your shell)
  2. a .env file in the current folder or next to this package
  3. ~/.jev_defense/config.json, written by `jevdefense key <key>`

Why the file: editors launched from the Dock (Cursor, Zed, VS Code) never read your shell
profile, so an exported variable is invisible to them. A 0600 file in your home folder is
readable by every host and by nobody else. (Idea from jev-guard.)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

HOME_DIR = Path(os.environ.get("JEV_DEFENSE_HOME", Path.home() / ".jev_defense"))
CONFIG_FILE = HOME_DIR / "config.json"
PACKAGE_ROOT = Path(__file__).resolve().parent.parent

# Total time one gate decision may take, retries included. Hosts kill a hook at ~30 s, and a
# killed hook is NOT a denial: in Claude Code a timed-out hook is a non-blocking error and the
# tool call goes ahead. So the guard must give up on its own, early enough to answer "ask".
TIMEOUT_S = float(os.environ.get("JEV_DEFENSE_TIMEOUT", "20"))


def _read_env_file(path: Path) -> dict[str, str]:
    out = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def read_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def resolve_api_key() -> str | None:
    for var in ("TYPESAFE_API_KEY", "JEV_API_KEY"):
        if var in os.environ:
            # Set-but-empty is a deliberate "no key" (tests and CI use it to stay offline),
            # so it must not fall through to a .env or config file on disk.
            return os.environ[var] or None
    for env_file in (Path(".env"), PACKAGE_ROOT / ".env"):
        values = _read_env_file(env_file)
        for var in ("TYPESAFE_API_KEY", "JEV_API_KEY"):
            if values.get(var):
                return values[var]
    return read_config().get("api_key") or None


def save_api_key(key: str) -> Path:
    HOME_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg = read_config()
    cfg["api_key"] = key.strip()
    # Create with 0600 from the start, so the key is never briefly world-readable.
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)
    return CONFIG_FILE


def fail_open() -> bool:
    """Default is fail CLOSED: an unreachable model means 'ask a human'. Opt out explicitly."""
    return os.environ.get("JEV_DEFENSE_FAIL_OPEN") == "1"
