from rich.console import Console
from rich.align import Align
from rich.panel import Panel
from rich.text import Text

from tracex import __version__

LOGO = """\
████████╗██████╗  █████╗  ██████╗███████╗██╗  ██╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝
   ██║   ██████╔╝███████║██║     █████╗   ╚███╔╝
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝   ██╔██╗
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██╔╝ ██╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝"""

_LINES = LOGO.splitlines()
_WIDTH = max(len(line) for line in _LINES)
# Pad every row to the same width so centering doesn't skew the logo.
LOGO_PADDED = "\n".join(line.ljust(_WIDTH) for line in _LINES)

TAGLINE = "Digital Footprint Investigator"

AUTHORIZED_NOTICE = (
    "Use TraceX only on targets you own or are explicitly authorized "
    "to assess. You are responsible for how you use it."
)


def show_banner(console: Console | None = None) -> None:
    console = console or Console()

    console.print(
        Panel(
            Align.center(Text(LOGO_PADDED, style="bold red", no_wrap=True)),
            title="[bold white]TraceX[/bold white]",
            subtitle=f"[red]{TAGLINE}[/red]",
            border_style="red",
            padding=(1, 3),
        )
    )
    console.print(
        f"[dim]  Authorized Reconnaissance Toolkit | Version {__version__}[/dim]\n"
    )
