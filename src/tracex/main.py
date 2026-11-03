from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from tracex import __version__
from tracex.banner import AUTHORIZED_NOTICE, show_banner
from tracex.core.models import ModuleResult
from tracex.core.registry import MODULES, SCAN_MODULES
from tracex.core.render import render_result, render_summary
from tracex.core.report import to_json, write_report
from tracex.core.runner import run_module
from tracex.menu import interactive_menu
from tracex.utils.validators import validate_domain, validate_http_target

app = typer.Typer(
    name="tracex",
    help="Digital Footprint Investigator",
    no_args_is_help=False,
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True)

JsonOpt = typer.Option(
    False, "--json", help="Print results as JSON (no banner/spinner)."
)
OutOpt = typer.Option(
    None, "--output", "-o", help="Save report to a .json or .md file."
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    TraceX - Digital Footprint Investigator.
    """

    # Interactive mode when no command is provided
    if ctx.invoked_subcommand is None:
        show_banner(console)
        interactive_menu()


def _execute(
    names: list[str],
    target: str,
    as_json: bool,
    output: Path | None,
    options: dict | None = None,
) -> None:
    results: list[ModuleResult] = []

    if not as_json:
        err_console.print(f"[dim]{AUTHORIZED_NOTICE}[/dim]\n")

    for name in names:
        try:
            result = run_module(console, name, target, quiet=as_json, options=options)
        except ValueError as error:
            err_console.print(f"[bold red][-] Error:[/bold red] {error}")
            raise typer.Exit(code=2)
        results.append(result)
        if not as_json:
            render_result(console, result)

    if as_json:
        print(to_json(results))
    else:
        render_summary(console, results)

    if output is not None:
        try:
            saved = write_report(results, output)
        except (ValueError, OSError) as error:
            err_console.print(
                f"[bold red][-] Could not save report:[/bold red] {error}"
            )
            raise typer.Exit(code=2)
        err_console.print(f"[green][+] Report saved:[/green] {saved}")

    if any(not r.ok for r in results):
        raise typer.Exit(code=1)


@app.command()
def validate(
    target: str = typer.Argument(
        ..., help="Domain, IP address, hostname or URL to validate."
    ),
):
    """
    Validate a domain, IP address, hostname or URL.
    """

    try:
        result = validate_http_target(target)
        console.print(f"[bold green][+] Valid target:[/bold green] {result}")

    except ValueError as error:
        console.print(f"[bold red][-] Error:[/bold red] {error}")
        raise typer.Exit(code=2)


@app.command()
def dns(
    domain: str = typer.Argument(..., help="Domain to resolve."),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """Look up DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA)."""
    _execute(["dns"], domain, as_json, output)


@app.command()
def whois(
    domain: str = typer.Argument(..., help="Domain to look up."),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """Registration info (registrar, dates, status) via RDAP."""
    _execute(["whois"], domain, as_json, output)


@app.command()
def subdomains(
    domain: str = typer.Argument(..., help="Domain to enumerate."),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """Passive subdomain discovery from Certificate Transparency logs."""
    _execute(["subdomains"], domain, as_json, output)


@app.command()
def http(
    domain: str = typer.Argument(..., help="Domain or host:port, e.g. localhost:8080."),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """HTTP headers, redirects, security headers and tech fingerprint."""
    _execute(["http"], domain, as_json, output)


@app.command()
def webscan(
    target: str = typer.Argument(
        ..., help="Domain or host:port, e.g. example.com or localhost:8080."
    ),
    deep: bool = typer.Option(
        False, "--deep", help="More checks and pages (up to 150 requests)."
    ),
    max_requests: int = typer.Option(
        None,
        "--max-requests",
        min=5,
        max=1000,
        help="Hard cap on HTTP requests (default 50).",
    ),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """Deep web audit: headers, exposed files, cookies, CORS, TLS, crawl."""
    _execute(
        ["webscan"],
        target,
        as_json,
        output,
        {"deep": deep, "max_requests": max_requests},
    )


@app.command()
def tools(
    target: str = typer.Argument(
        ..., help="Host or host:port to scan with installed tools."
    ),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """Run installed external tools (nmap service scan, whatweb)."""
    _execute(["tools"], target, as_json, output)


@app.command()
def username(
    name: str = typer.Argument(..., help="Username to look for."),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """Check for public profiles with this username on common sites."""
    _execute(["username"], name, as_json, output)


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Domain to scan with all domain modules."),
    deep: bool = typer.Option(
        False, "--deep", help="Deeper web audit (up to 150 requests)."
    ),
    as_json: bool = JsonOpt,
    output: Path = OutOpt,
):
    """Run dns, whois, subdomains and the deep webscan in one go."""
    _execute(SCAN_MODULES, domain, as_json, output, {"deep": deep} if deep else None)


@app.command()
def modules():
    """List available modules."""
    for name, module in MODULES.items():
        console.print(f"[bold red]{name:<11}[/bold red] {module.description}")


@app.command()
def version():
    """
    Display TraceX version.
    """

    console.print(f"[bold red]TraceX[/bold red] version [white]{__version__}[/white]")


if __name__ == "__main__":
    app()
