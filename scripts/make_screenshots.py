#!/usr/bin/env python3
"""Regenerate the README screenshots (docs/*.svg) from TraceX's real output.

Start the demo target first:   python examples/vulnerable_demo.py
Then:                          python scripts/make_screenshots.py
"""

import io
from pathlib import Path

from rich.console import Console

from tracex import menu
from tracex.banner import show_banner
from tracex.core.render import render_summary
from tracex.core.runner import run_and_render

DOCS = Path(__file__).resolve().parent.parent / "docs"
TARGET = "localhost:8000"


def recorder(width: int = 100) -> Console:
    return Console(
        record=True, file=io.StringIO(), width=width, force_terminal=True, color_system="truecolor"
    )


def main() -> None:
    DOCS.mkdir(exist_ok=True)

    console = recorder()
    show_banner(console)
    menu.console = console
    menu._print_menu()
    console.save_svg(str(DOCS / "banner-menu.svg"), title="tracex")

    console = recorder()
    result = run_and_render(console, "webscan", TARGET)
    render_summary(console, [result])
    console.save_svg(str(DOCS / "webscan.svg"), title=f"tracex webscan {TARGET}")
    print("Saved docs/banner-menu.svg and docs/webscan.svg")


if __name__ == "__main__":
    main()
