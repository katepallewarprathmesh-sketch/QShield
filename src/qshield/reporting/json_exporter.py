"""JSON export for QSHIELD scan results."""

from __future__ import annotations

import json
from typing import Any


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=False, default=str)
