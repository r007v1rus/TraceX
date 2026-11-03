from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ModuleResult:
    """Outcome of running one module against one target."""

    module: str
    target: str
    ok: bool = True
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
