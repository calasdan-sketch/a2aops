"""Shared spec knowledge loader.

All spec facts live in spec_snapshot.json, pinned to a spec version. Code must
not hardcode spec facts that live in the snapshot.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_SNAPSHOT_PATH = Path(__file__).with_name("spec_snapshot.json")


@lru_cache(maxsize=1)
def load_spec() -> dict:
    """Load the pinned spec snapshot (cached)."""
    return json.loads(_SNAPSHOT_PATH.read_text(encoding="utf-8"))


def spec_version() -> str:
    return str(load_spec()["spec_version"])
