# Contributing to TraceX

Thanks for helping! A few ground rules keep the project useful and safe.

## Scope

TraceX is a **read-only reconnaissance and audit** tool. Contributions should be:

- **Passive or low-impact:** ordinary requests only (GET/HEAD/OPTIONS, DNS, public APIs).
- **Budgeted:** HTTP modules must go through `core.fetcher.Fetcher` so the request budget is enforced.
- **Defensive in purpose:** every finding should come with a `fix`.

Please do **not** submit exploit code, brute-forcing, credential guessing, denial-of-service
checks, or anything that modifies the target.

## Development setup

```bash
git clone https://github.com/<your-username>/TraceX
cd TraceX
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

## Adding a module or check

- Extend `tracex.core.base.Module` and return findings built with `tracex.core.findings.finding()`.
- Keep detection **content-validated** (match what the file actually contains) to avoid false positives.
- Add tests. Prefer a real local server or a fake resolver over mocking internals. Tests must run offline.
- Update the README feature table and `CHANGELOG.md`.

## Pull requests

- One logical change per PR, with tests.
- `pytest` must pass on Python 3.11, 3.12 and 3.13 (CI checks this).
- Describe what the change detects and why it matters.

## Reporting false positives

Open an issue with the target type (never a real site you don't own), the command, and the output.
