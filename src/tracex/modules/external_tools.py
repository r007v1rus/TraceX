"""Wrappers around well-known tools, run only if they are installed.

Commands are built as argument lists (never through a shell) from a validated
host, so nothing user-supplied can inject extra options.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

from tracex.core.base import Module, ModuleError
from tracex.utils.validators import validate_http_target

TIMEOUT = {"nmap": 300, "whatweb": 120}
INSTALL_HINT = "Install nmap and/or whatweb (e.g. `sudo apt install nmap whatweb`, `brew install nmap whatweb`)."


def parse_nmap_xml(xml_text: str) -> list[dict[str, str]]:
    """Open ports with service details from `nmap -oX -` output."""
    ports: list[dict[str, str]] = []
    root = ET.fromstring(xml_text)
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        svc = svc if svc is not None else ET.Element("service")
        ports.append(
            {
                "port": f"{port.get('portid')}/{port.get('protocol')}",
                "service": svc.get("name", "-"),
                "product": " ".join(
                    x for x in (svc.get("product"), svc.get("version"), svc.get("extrainfo")) if x
                ) or "-",
            }
        )
    return ports


def parse_whatweb_json(text: str) -> list[str]:
    """Plugin names (with version where known) from whatweb --log-json output."""
    try:
        records = json.loads(text)
    except ValueError:
        records = []
        for line in text.splitlines():
            line = line.strip().rstrip(",").lstrip("[").rstrip("]")
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    found: set[str] = set()
    for record in records if isinstance(records, list) else [records]:
        for plugin, details in (record.get("plugins") or {}).items():
            version = ""
            if isinstance(details, dict) and details.get("version"):
                version = " " + ", ".join(map(str, details["version"]))
            found.add(plugin + version)
    return sorted(found)


class ExternalTools(Module):
    name = "tools"
    description = "Run installed tools (nmap service scan, whatweb) and merge their results"
    # "host" targets are not included in the all-in-one `scan` command.
    target_type = "host"

    def validate(self, target: str) -> str:
        return validate_http_target(target)

    @staticmethod
    def _split(target: str) -> tuple[str, str, int | None]:
        parts = urlsplit(target if "://" in target else f"//{target}")
        return parts.scheme or "http", parts.hostname or "", parts.port

    def _run(self, args: list[str], tool: str) -> str:
        done = subprocess.run(
            args, capture_output=True, text=True, timeout=TIMEOUT[tool], shell=False
        )
        if done.returncode != 0 and not done.stdout.strip():
            raise ModuleError(f"{tool} failed: {done.stderr.strip()[:200] or done.returncode}")
        return done.stdout

    def collect(self, target: str, **_: Any) -> dict[str, Any]:
        scheme, host, port = self._split(target)
        available = {t: shutil.which(t) for t in ("nmap", "whatweb")}
        if not any(available.values()):
            raise ModuleError("No supported tools found. " + INSTALL_HINT)

        data: dict[str, Any] = {
            "tools_run": [],
            "tools_missing": [t for t, path in available.items() if not path],
            "open_ports": [],
            "whatweb": [],
            "notes": [],
        }

        if available["nmap"]:
            args = ["nmap", "-sV", "--version-intensity", "5", "-T3", "--open", "-oX", "-"]
            args += ["-p", str(port)] if port else ["--top-ports", "100"]
            args.append(host)
            try:
                data["open_ports"] = parse_nmap_xml(self._run(args, "nmap"))
                data["tools_run"].append("nmap")
            except subprocess.TimeoutExpired:
                data["notes"].append("nmap timed out")
            except (ET.ParseError, ModuleError) as error:
                data["notes"].append(f"nmap: {error}")

        if available["whatweb"]:
            url = f"{scheme}://{host}" + (f":{port}" if port else "")
            args = ["whatweb", "-a", "1", "--no-errors", "--log-json=-", url]
            try:
                data["whatweb"] = parse_whatweb_json(self._run(args, "whatweb"))
                data["tools_run"].append("whatweb")
            except subprocess.TimeoutExpired:
                data["notes"].append("whatweb timed out")
            except ModuleError as error:
                data["notes"].append(str(error))

        if not data["tools_run"]:
            raise ModuleError("; ".join(data["notes"]) or "No tool produced output.")
        return data
