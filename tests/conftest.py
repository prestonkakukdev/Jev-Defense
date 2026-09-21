import os
import sys
import tempfile
from pathlib import Path

# Isolate every test run from the real ~/.agent_defense (sessions, scan cache, saved key).
# Must happen before agent_defense is imported, because config.HOME_DIR is read at import.
os.environ["AGENT_DEFENSE_HOME"] = tempfile.mkdtemp(prefix="agentdefense-test-home-")
os.environ.pop("AGENT_DEFENSE_STATE_DIR", None)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
