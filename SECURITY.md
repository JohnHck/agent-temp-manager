# Security policy

Agent Temp Manager deletes files when, and only when, an operator approves exact paths. Reports about any way
to make it delete something that is not an approved, eligible session root, to traverse a reparse point, to
bypass a gate from the TUI, or to expose command lines, tokens or file contents are treated as security issues.

Please report privately through the repository's security advisory feature ("Report a vulnerability")
rather than a public issue. Include the Windows and PowerShell versions and a minimal reproduction using a
throw-away directory, never real user data.

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for the threat model and documented limitations.
