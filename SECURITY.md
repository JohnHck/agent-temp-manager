# Security policy

Agent Temp Manager deletes files when, and only when, an operator approves exact paths. Reports about any way
to make it delete something that is not an approved, eligible session root, to traverse a reparse point, to
bypass a gate from the TUI, or to expose command lines, tokens or file contents are treated as security issues.

## Supported versions

Only the latest published line receives fixes. Today that is 0.3.x: the latest published version is 0.3.0.

| Version | Supported | Notes |
|---|---|---|
| 0.3.x | Yes | Security fixes are released as 0.3.y. |
| 0.2.x | No | Update to the latest 0.3.x. |
| 0.1.x | No | Update to the latest 0.3.x. |

When a newer line is published (for example 0.4.x), only that line is supported.

The installer updates an installation in place from the published versions; the install end-to-end test updates from
each of them (0.1.0, 0.1.1, 0.2.0 and 0.3.0, see [docs/TESTING.md](docs/TESTING.md)). How to update:
[docs/INSTALL.md](docs/INSTALL.md#update).

Fixes already published for a line that is no longer supported stay valid (for example 0.1.1, a security fix of 0.1.0
published from the `release/0.1.x` branch), but no new ones will be released for that line.

## Reporting a vulnerability

Please report privately through the repository's security advisory feature ("Report a vulnerability")
rather than a public issue. Include the Windows and PowerShell versions and a minimal reproduction using a
throw-away directory, never real user data.

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for the threat model and documented limitations.
