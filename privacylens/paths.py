"""Location policy for non-sensitive run artifacts."""
import os
from pathlib import Path
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_DIR_ENV = "PRIVACYLENS_RUN_DIR"


def get_run_output_dir() -> Path:
    configured = os.environ.get(RUN_DIR_ENV)
    path = Path(configured).expanduser() if configured else Path(tempfile.gettempdir()) / "privacylens-runs"
    path = path.resolve()
    try:
        path.relative_to(PROJECT_ROOT)
    except ValueError:
        pass
    else:
        raise ValueError("run output directory must be outside the project folder")
    path.mkdir(parents=True, exist_ok=True)
    return path
