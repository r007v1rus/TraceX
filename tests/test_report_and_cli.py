import json

from typer.testing import CliRunner

from tracex import __version__
from tracex.banner import LOGO
from tracex.core import registry
from tracex.core.models import ModuleResult
from tracex.core.report import to_json, to_markdown, write_report
from tracex.main import app

runner = CliRunner()


def sample():
    return [
        ModuleResult("dns", "example.com", data={"records": {"A": ["1.1.1.1"]}}),
        ModuleResult("whois", "example.com", ok=False, error="boom"),
    ]


def test_json_report():
    payload = json.loads(to_json(sample()))
    assert payload["tool"] == "TraceX"
    assert payload["results"][0]["data"]["records"]["A"] == ["1.1.1.1"]
    assert payload["results"][1]["error"] == "boom"


def test_markdown_report():
    md = to_markdown(sample())
    assert "## dns" in md and "1.1.1.1" in md and "**Error:** boom" in md


def test_write_report(tmp_path):
    assert write_report(sample(), tmp_path / "r.md").read_text().startswith("# TraceX")
    write_report(sample(), tmp_path / "r.json")
    try:
        write_report(sample(), tmp_path / "r.txt")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0 and __version__ in result.output


def test_validate_command():
    ok = runner.invoke(app, ["validate", "Example.com"])
    assert ok.exit_code == 0 and "example.com" in ok.output
    bad = runner.invoke(app, ["validate", "1.2.3.4"])
    assert bad.exit_code == 1


def test_invalid_target_exit_code():
    assert runner.invoke(app, ["dns", "not a domain"]).exit_code == 2


def test_json_flag_outputs_clean_json(monkeypatch):
    class Fake:
        name, description, target_type = "dns", "x", "domain"

        def validate(self, target):
            return target

        def run(self, target):
            return ModuleResult("dns", target, data={"records": {}})

    monkeypatch.setitem(registry.MODULES, "dns", Fake())
    from tracex.core import runner as core_runner
    monkeypatch.setitem(core_runner.MODULES, "dns", Fake())

    result = runner.invoke(app, ["dns", "example.com", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["results"][0]["target"] == "example.com"


def test_interactive_requires_authorization():
    result = runner.invoke(app, [], input="n\n")
    assert "Authorization is required" in result.output


def test_interactive_menu_and_exit():
    result = runner.invoke(app, [], input="y\n10\n00\n")
    assert result.exit_code == 0
    assert LOGO.splitlines()[0] in result.output  # banner rendered
    assert "MAIN MENU" in result.output and "Goodbye" in result.output


def test_interactive_domain_validation():
    result = runner.invoke(app, [], input="y\n01\nexample.com\n01\n10.0.0.1\n00\n")
    assert "VALID DOMAIN" in result.output and "INVALID DOMAIN" in result.output
