import sys
from pathlib import Path


#Ensure repo root is in sys.path, so tests can import src modules
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))