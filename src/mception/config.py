"""Runtime configuration loaded from env vars."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Settings(BaseModel):
    # Where we store audit reports + baselines.
    data_dir: Path = Path(
        os.environ.get("MCEPTION_DATA_DIR", str(Path.home() / ".mception"))
    )
    # Opt-in LLM-assisted classification of ambiguous descriptions.
    # When enabled, rules that need a model use the host's MCP `sampling/createMessage`
    # primitive — whatever model the host agent is already running — so no API key is needed.
    # If the host does not implement sampling, the judge is silently skipped.
    enable_llm_judge: bool = _env_bool("MCEPTION_ENABLE_LLM_JUDGE", False)
    # Hard cap on how long an introspection attempt may take.
    introspect_timeout_s: int = int(os.environ.get("MCEPTION_INTROSPECT_TIMEOUT", "60"))
    # Whether fetchers are allowed to reach the network (npm/pypi/git).
    offline_mode: bool = _env_bool("MCEPTION_OFFLINE", False)
    # Filename (relative to the target workdir) of the per-target suppression
    # policy. See `src/mception/engines/baseline.py:load_suppressions`.
    suppressions_filename: str = os.environ.get("MCEPTION_SUPPRESSIONS_FILE", ".mception.yml")

    def ensure_data_dir(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "audits").mkdir(exist_ok=True)
        (self.data_dir / "baselines").mkdir(exist_ok=True)
        return self.data_dir


settings = Settings()
