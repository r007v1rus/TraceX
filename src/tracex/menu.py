from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from tracex import __version__
from tracex.banner import AUTHORIZED_NOTICE
from tracex.core.models import ModuleResult
from tracex.core.registry import MODULES, SCAN_MODULES
from tracex.core.render import render_result, render_summary
from tracex.core.report import write_report
from tracex.core.runner import run_and_render, run_module
from tracex.utils.validators import validate_domain

console = Console()

# menu number -> (label, module name or special action)
ENTRIES = {
    "01": ("Domain validation", None),
    "02": ("DNS records", "dns"),
    "03": ("WHOIS / registration (RDAP)", "whois"),
    "04": ("Subdomain discovery (CT logs)", "subdomains"),
    "05": ("HTTP headers & tech fingerprint (quick)", "http"),
    "06": ("Deep web scan (exposure, cookies, CORS, TLS, crawl)", "webscan"),
    "07": ("External tools (nmap, whatweb)", "tools"),
    "08": ("Username presence check", "username"),
    "09": ("Full domain scan", "scan"),
    "10": ("About TraceX", None),
    "00": ("Exit", None),
}

MODULE_CHOICES = ("02", "03", "04", "05", "06", "07", "08")


def _print_menu() -> None:
    console.print("\n[bold red]MAIN MENU[/bold red]\n")
    for key, (label, _) in ENTRIES.items():
        console.print(f"[red][{key}][/red] {label}")
    console.print()


def _ask_target(module_name: str) -> str:
    kind = MODULES[module_name].target_type
    if module_name in ("http", "webscan", "tools"):
        kind = "domain or host:port"
    return Prompt.ask(f"\n[bold]Enter {kind}[/bold]")


def _offer_export(results: list[ModuleResult]) -> None:
    if Confirm.ask("Save results to a file?", default=False):
        path = Prompt.ask("File name (.json or .md)", default="tracex-report.md")
        try:
            console.print(f"[green]Saved:[/green] {write_report(results, path)}")
        except (ValueError, OSError) as error:
            console.print(f"[bold red]Could not save:[/bold red] {error}")


def _run_one(module_name: str) -> None:
    target = _ask_target(module_name)
    options = None
    if module_name == "webscan":
        deep = Confirm.ask("Deep mode (up to 150 requests instead of 50)?", default=False)
        options = {"deep": deep}
    try:
        result = run_and_render(console, module_name, target, options)
    except ValueError as error:
        console.print(f"\n[bold red]INVALID TARGET[/bold red] : {error}\n")
        return
    _offer_export([result])


def _run_scan() -> None:
    target = _ask_target("dns")
    try:
        domain = validate_domain(target)
    except ValueError as error:
        console.print(f"\n[bold red]INVALID DOMAIN[/bold red] : {error}\n")
        return

    results = []
    for name in SCAN_MODULES:
        result = run_module(console, name, domain)
        render_result(console, result)
        results.append(result)
    render_summary(console, results)
    _offer_export(results)


def interactive_menu() -> None:
    console.print(f"[dim]{AUTHORIZED_NOTICE}[/dim]\n")
    if not Confirm.ask("[bold]I am authorized to assess my targets[/bold]", default=False):
        console.print("\n[bold red]Exiting.[/bold red] Authorization is required.\n")
        return

    while True:
        _print_menu()
        choice = Prompt.ask(
            "[bold red]tracex[/bold red]", choices=list(ENTRIES), default="01"
        )

        if choice == "01":
            domain = Prompt.ask("\n[bold]Enter domain[/bold]")
            try:
                console.print(
                    f"\n[bold green]VALID DOMAIN[/bold green] : {validate_domain(domain)}\n"
                )
            except ValueError as error:
                console.print(f"\n[bold red]INVALID DOMAIN[/bold red] : {error}\n")

        elif choice in MODULE_CHOICES:
            _run_one(ENTRIES[choice][1])

        elif choice == "09":
            _run_scan()

        elif choice == "10":
            console.print(
                Panel(
                    "A modular digital footprint investigation toolkit "
                    "for authorized reconnaissance.\n\n"
                    f"Modules: {', '.join(MODULES)}",
                    title=f"[bold red]TraceX {__version__}[/bold red]",
                    border_style="red",
                )
            )

        elif choice == "00":
            console.print("\n[bold red]Goodbye![/bold red]\n")
            break
