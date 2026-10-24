# ADR-0008: Provider contract v2 and the Claude Desktop scenario

Status: ACCEPTED (maintainer gate 2026-10-20, after PR #19)
Date: 2026-10-20
Phase: P1 (contract and Claude Code runtime members), P2 (Claude Desktop provider)

## Context

The V0.1 contract (`docs/PROVIDERS.md`) describes temporary directories and session liveness: `Register-AtmProvider`
requires all eleven members (`Id`, `DisplayName`, `TempSubdir`, `ScopePattern`, `RootPattern`, `EnvVarNames`,
`GetExtraTempDirs`, `GetConfigDirs`, `GetSessionEvidence`, `GetActivityEvidence`, `GetProjectKey`) and the inventory
iterates every provider over every TEMP candidate. V0.2 needs providers to describe **runtime** evidence (process
signatures, services, virtual machines, worktree locations). The Claude Desktop scenario may have no per-session
temporary directories at all, so it cannot satisfy the V0.1 members. Agents remain optional: the tool must work, and
report correctly, with no provider's agent installed.

The diagnostics process matcher is needed in P1 (agent-related processes), so the contract change cannot wait for P2,
where the Claude Desktop provider is added.

## Decision

1. **Versioned contract.** A provider may declare `ContractVersion = 2` and `Capabilities` (a subset of `temp`,
   `runtime`). A provider without `ContractVersion` is a v1 provider: validated exactly as today and treated as
   `Capabilities = @('temp')`. Existing providers, including third-party ones written for V0.1, keep working unchanged.
2. **Members by capability:**
   * `temp`: the eleven V0.1 members, unchanged, same validation.
   * `runtime` (all optional, absent means "no hints", never "nothing running"):

     | Member | Returns |
     |---|---|
     | `GetProcessMatchers` | `@({ ImageName; CommandLineMarker })`: exact image file name, optional marker matched in memory against the command line (never stored, as in V0.1). |
     | `GetServiceHints` | `@({ Name; Role })`: exact service names (ADR-0005). |
     | `GetVirtualizationHints` | `@({ Kind; Value })`: for example an owning service name or a VM name the agent creates (ADR-0005). |
     | `GetWorktreeHints` | `{ param($ProfileInfo, $Registry) }` -> starting directories (ADR-0007), with `Readable` like other evidence members. |
3. The temporary inventory iterates only providers with the `temp` capability; the diagnose engine iterates providers
   with `runtime`. A provider may have both (Claude Code will).
4. **Rules unchanged:** providers only read, never decide, never classify, never open credential or token files, and
   report "cannot look" (`Readable = $false`) instead of "nothing found". A provider can never weaken a gate or a
   coverage status.
5. **Claude Code** (P1) gains `runtime` members: process matchers and worktree hints from its session registry
   (`sessions\<pid>.json` `cwd`, read as today; the full path is used in memory for resolution and reported only per
   ADR-0007 D-5).
6. **Claude Desktop** (P2) is a new provider file `src/providers/ClaudeDesktop.ps1` with `Capabilities = @('runtime')`
   (plus `temp` only if real temporary per-session directories are confirmed). Its signatures (image names, service
   names such as `CoworkVMService`, VM hints) are confirmed by read-only observation on a machine where it is
   installed, and recorded in the provider with the Claude Desktop version and date observed. No file of the desktop
   application is required for the tool to run; absence of the application is `NOT_PRESENT` for its hints.
7. The installer manifest and the launcher already load every listed provider file; a new provider file is added to
   the release like any source file (no installer change expected; verified by the existing manifest tests).

## Rejected alternatives

* *Making every V0.1 member optional:* weakens validation for temporary-directory providers, whose members feed the
  deletion gates.
* *A separate "scenario" plug-in type:* duplicates registration, manifest and test machinery for no gain.
* *Hard-coding Claude Desktop names in the engine:* contradicts "generic architecture"; the engine must not know agents.

## Consequences

* `docs/PROVIDERS.md` gets a v2 section; the v1 table stays valid.
* Third-party providers can opt in to runtime hints without touching temporary-directory behaviour.

## Verification

* Existing test "provider ficticio" and the backward-compatibility test for `param($Profile)` stay green unchanged.
* New tests: a runtime-only fictional provider registers without the temp members and is ignored by the inventory; a
  v2 provider missing a required temp member while declaring `temp` is refused; malformed runtime members are refused
  at registration; a provider whose hint function throws gives coverage `FAILED`, not "no hints".
* Inventory and diagnose run correctly with no provider's agent installed (fixtures without any config directory,
  process or service).

## Implementation record (P2-C, 2026-10-24)

Decision 6 implemented: `src/providers/ClaudeDesktop.ps1` (id `claude-desktop`, `ContractVersion = 2`,
`Capabilities = @('runtime')`). The contract and the engine are unchanged.

* **Signatures and their basis** (the file records each source; details in `docs/PROVIDERS.md`): process `claude.exe`
  with the marker `pzs8sxrjxfjjc` (publisher id of the documented package family name `Claude_pzs8sxrjxfjjc`, which
  the MSIX install folder carries); service `CoworkVMService` (role `cowork-vm`), a name publicly reported in
  Anthropic's issue tracker with Claude Desktop 1.1.3647 (2026-02-19) and later (2026-05-14), not named in
  Anthropic's documentation. Decision 6 asked for read-only observation on a machine with Claude Desktop: no such
  machine was available to this phase (the CI runners have none), so the signatures rest on the documentation and
  on public reports, and the real installation is NOT_TESTED.
* **Not declared:** virtualization hints (the Cowork VM is an HCS compute system named `cowork-vm-<8 hex>`, not in
  `Msvm_ComputerSystem`; no service -> worker relation is verifiable), temporary directories (none confirmed), and
  any installation version (none is read).
* **Overlap with Claude Code:** both providers match `claude.exe` (Claude Code by image, Claude Desktop by image and
  marker), so a package process is attributable to both and reported as ambiguous. A provider whose marker could not
  be checked (unreadable command line) now takes part in the attribution (engine change of P2-C, review): the process
  stays ambiguous instead of being resolved to Claude Code. Every `claude.exe` with an unreadable command line makes
  `agent-processes` `PARTIAL`, also on machines without Claude Desktop. Narrowing Claude Code's matcher would change
  a P1 provider and is left to a later decision.
* **What the diagnose can say about Cowork:** a running `CoworkVMService` with a verified process (local service
  evidence); never that a Cowork VM runs or does not run, and nothing about Cowork in a remote environment.
