import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
# The `benchmark` package lives at the repo root, not under src/, so tests
# for it need the root on the path too.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
