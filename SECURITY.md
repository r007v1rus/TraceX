# Security Policy

## Responsible use

TraceX is for **authorized** assessments only. Do not run it against systems you do not own
or have written permission to test. Misuse is your responsibility.

## Reporting a vulnerability in TraceX

If you find a security issue in TraceX itself (for example command injection through a
target string, unsafe file writes in report export, or a bypass of the request budget),
please report it privately through GitHub's **Security > Report a vulnerability** form
rather than a public issue. Include steps to reproduce and the version (`tracex version`).

You can expect an acknowledgement within a few days and a fix or mitigation as soon as practical.

## Design notes

- External tools are executed as argument lists without a shell, with targets validated first.
- Secrets found in client-side code are masked in all output.
- HTTP requests are capped by a hard budget and limited to the target's own origin when crawling.
