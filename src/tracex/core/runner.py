from __future__ import annotations

from rich.console import Console

from tracex.core.models import ModuleResult
from tracex.core.registry import MODULES
from tracex.core.render import render_result


def validate_target(module_name: str, target: str) -> str:
    """Validate/normalise a target for the given module. Raises ValueError."""
    return MODULES[module_name].validate(target)


def run_module(
    console: Console,
    module_name: str,
    target: str,
    quiet: bool = False,
    options: dict | None = None,
) -> ModuleResult:
    module = MODULES[module_name]
    target = validate_target(module_name, target)
    options = options or {}
    if quiet:
        return module.run(target, **options)
    with console.status(f"[red]Running {module_name} on {target}...[/red]"):
        return module.run(target, **options)


def run_and_render(
    console: Console, module_name: str, target: str, options: dict | None = None
) -> ModuleResult:
    result = run_module(console, module_name, target, options=options)
    render_result(console, result)
    return result
