from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tracex.core.findings import SEVERITY_STYLE, build_summary
from tracex.core.models import ModuleResult

MAX_ROWS = 25  # long lists/tables are truncated on screen; reports keep everything

# Kept in JSON/Markdown reports but not printed (already covered by findings).
HIDDEN_KEYS = {"exposed_paths"}

GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "bold yellow", "F": "bold red"}


def _fmt(v: Any) -> str:
    if v in (None, "", [], {}):
        return "-"
    if isinstance(v, list):
        items = [str(i) for i in v]
        if len(items) > MAX_ROWS:
            items = items[:MAX_ROWS] + [f"... {len(v) - MAX_ROWS} more (use --output / --json for all)"]
        return "\n".join(items)
    if isinstance(v, dict):
        return "\n".join(f"{k}: {_fmt(x)}" for k, x in v.items())
    return str(v)


def _table_for(value: Any):
    # list of dicts -> columnar table
    if isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
        table = Table(border_style="red", header_style="bold red")
        cols = list(value[0].keys())
        for col in cols:
            table.add_column(str(col))
        for row in value[:MAX_ROWS]:
            table.add_row(*[_fmt(row.get(c)) for c in cols])
        if len(value) > MAX_ROWS:
            table.add_row(f"... {len(value) - MAX_ROWS} more", *[""] * (len(cols) - 1))
        return table
    return None


def _findings_table(findings: list[dict]) -> Table:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True)
    grid.add_column(ratio=1)
    for f in findings:
        sev = f["severity"]
        body = Text()
        body.append(f["title"], style="bold")
        if f.get("detail"):
            body.append(f"  {f['detail']}", style="dim")
        if f.get("fix") and sev != "info":
            body.append(f"\nfix: {f['fix']}", style="green")
        grid.add_row(Text(f" {sev.upper():<6} ", style=f"reverse {SEVERITY_STYLE[sev]}"), body)
    return grid


def _counts_line(counts: dict[str, int]) -> Text:
    text = Text()
    for sev, n in counts.items():
        text.append(f"{n} {sev}", style=SEVERITY_STYLE[sev] if n else "dim")
        text.append("   ")
    return text


def render_result(console: Console, result: ModuleResult) -> None:
    title = f"[bold red]{result.module}[/bold red] [dim]{result.target}[/dim]"

    if not result.ok:
        console.print(
            Panel(f"[bold red]Error:[/bold red] {result.error}", title=title, border_style="red")
        )
        return

    parts: list[Any] = []
    kv = Table.grid(padding=(0, 2))
    kv.add_column(style="bold")
    kv.add_column()
    has_kv = False
    data = result.data

    for key, value in data.items():
        if key == "score" or key in HIDDEN_KEYS:
            continue
        if value is None or value == [] or value == {}:
            continue
        if key == "grade":
            style = GRADE_STYLE.get(value, "")
            kv.add_row("grade", Text(f"{value}  ({data.get('score', '?')}/100)", style=style))
            has_kv = True
        elif key == "summary" and isinstance(value, dict) and all(isinstance(v, int) for v in value.values()):
            kv.add_row("findings", _counts_line(value))
            has_kv = True
        elif key == "findings":
            if value:
                parts.append("[bold]findings[/bold]")
                parts.append(_findings_table(value))
            else:
                kv.add_row("findings", "[green]none[/green]")
                has_kv = True
        else:
            table = _table_for(value)
            if table is not None:
                parts.append(f"[bold]{key}[/bold]")
                parts.append(table)
            else:
                kv.add_row(str(key), _fmt(value))
                has_kv = True

    body = Group(*(([kv] if has_kv else []) + parts)) if (has_kv or parts) else "[dim]No data.[/dim]"
    console.print(Panel(body, title=title, border_style="red"))


def render_summary(console: Console, results: list[ModuleResult]) -> None:
    """Overall grade and the most important fixes across all modules."""
    if len(results) < 2 or not any("findings" in r.data for r in results if r.ok):
        return
    s = build_summary(results)
    lines = Text()
    lines.append("Security grade  ", style="bold")
    lines.append(f"{s['grade']}", style=GRADE_STYLE.get(s["grade"], ""))
    lines.append(f"  ({s['score']}/100)\n", style="dim")
    lines.append_text(_counts_line(s["counts"]))
    if s["top_actions"]:
        lines.append("\n\nFix first:\n", style="bold")
        for i, a in enumerate(s["top_actions"], 1):
            lines.append(f" {i}. ", style="bold")
            lines.append(f"[{a['severity']}] ", style=SEVERITY_STYLE[a["severity"]])
            lines.append(f"{a['title']}\n")
            lines.append(f"    {a['fix']}\n", style="dim green")
    console.print(Panel(lines, title="[bold red]Summary[/bold red]", border_style="red"))
