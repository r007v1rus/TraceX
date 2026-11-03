from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from tracex.core.models import ModuleResult
from tracex.utils.validators import validate_domain, validate_username


class ModuleError(Exception):
    """Expected, user-presentable failure inside a module."""


class Module(ABC):
    """Base class for every TraceX module."""

    name: str = ""
    description: str = ""
    # "domain" or "username": decides how the target is validated.
    target_type: str = "domain"

    def validate(self, target: str) -> str:
        """Validate/normalise a raw target. Raises ValueError."""
        if self.target_type == "username":
            return validate_username(target)
        return validate_domain(target)

    @abstractmethod
    def collect(self, target: str, **options: Any) -> dict[str, Any]:
        """Gather data for an already-validated target."""

    def run(self, target: str, **options: Any) -> ModuleResult:
        try:
            data = self.collect(target, **options)
        except ModuleError as error:
            return ModuleResult(self.name, target, ok=False, error=str(error))
        except Exception as error:  # network/library errors must not crash the CLI
            return ModuleResult(
                self.name, target, ok=False, error=f"{type(error).__name__}: {error}"
            )
        return ModuleResult(self.name, target, data=data)
