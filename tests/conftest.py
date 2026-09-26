import os
import sys
import tempfile
from pathlib import Path

# Isolate every test run from the real ~/.jev_defense (sessions, scan cache, saved key).
# Must happen before jev_defense is imported, because config.HOME_DIR is read at import.
os.environ["JEV_DEFENSE_HOME"] = tempfile.mkdtemp(prefix="jevdefense-test-home-")
os.environ.pop("JEV_DEFENSE_STATE_DIR", None)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
