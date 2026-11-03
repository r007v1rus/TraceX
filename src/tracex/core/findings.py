"""Shared finding model, scoring and grading used by every module."""

from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}
# Points deducted from 100 per finding of each severity.
PENALTY = {"high": 15, "medium": 5, "low": 1, "info": 0}


def finding(severity: str, title: str, detail: str = "", fix: str = "") -> dict[str, str]:
    return {"severity": severity, "title": title, "detail": detail, "fix": fix}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}


def grade_for(score: int) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= threshold:
            return letter
    return "F"


def build_summary(results: list) -> dict[str, Any]:
    """Combine findings from every successful result into one overall verdict."""
    findings: list[dict] = []
    for r in results:
        if not r.ok:
            continue
        for f in r.data.get("findings", []):
            findings.append({**f, "module": r.module})

    counts = count_by_severity(findings)
    score = max(0, 100 - sum(PENALTY[s] * n for s, n in counts.items()))

    seen: set[str] = set()
    actions: list[dict] = []
    for f in sort_findings(findings):
        if f["severity"] in ("high", "medium", "low") and f.get("fix") and f["title"] not in seen:
            seen.add(f["title"])
            actions.append({"severity": f["severity"], "title": f["title"], "fix": f["fix"]})

    return {
        "score": score,
        "grade": grade_for(score),
        "counts": counts,
        "total_findings": len(findings),
        "top_actions": actions[:10],
        "modules_run": [r.module for r in results],
        "modules_failed": [r.module for r in results if not r.ok],
    }
