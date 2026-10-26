# Releasing

* Versioning: SemVer. The single source of truth is `$script:AtmVersion` in `src/lib/Engine.Audit.ps1`.
* Update `CHANGELOG.md`.
* The release gate `$script:AtmRealDeletionEnabled` in `src/lib/Engine.Clean.ps1` must stay `$false` unless a
  specific, documented authorization enables real deletion for that release.
* Build (runs the tests first):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Build-Release.ps1
```

Output: `dist/agent-temp-manager-<version>.zip` (with `src/manifest.json`) and `dist/SHA256SUMS.txt`.
`dist/` is not versioned.

* Run the suite on Windows PowerShell 5.1 **and** PowerShell 7 (CI does both).
* `Build-Release.ps1` runs `tools/Test-AtmPrivacy.ps1` on the exact staged content and refuses the release on
  any finding (SIDs, e-mails, user-profile paths, tokens, machine names, the build machine's own user/profile
  names, and optional private identifiers from `ATM_PRIVATE_NEEDLES`, a file kept outside the repository).
* Before the first public commit, check the author identity (`git config user.name/user.email`) and run
  `git gc --prune=now` so no unreachable local objects remain.
* Tag `v<version>` and attach the zip and `SHA256SUMS.txt` to the release. Publishing is a manual,
  maintainer-approved step.

## Publication checklist

1. Release gate: `$script:AtmRealDeletionEnabled = $false` (V0.1). `Build-Release.ps1` refuses archives without it.
2. Test suite green on Windows PowerShell 5.1 **and** PowerShell 7 (`NAO_TESTADO` items reviewed and listed in
   the release notes).
3. Clean-environment run (`tools/clean-env`) on Windows Sandbox or a fresh VM: `summary.json` with `allPassed`; and
   the CI `install e2e` jobs green for the release commit (real installation on disposable VMs). If the
   maintainer-machine run is not done, the release notes say so.
4. Privacy: `tools/Test-AtmPrivacy.ps1 -Path .` and on the built zip: no findings (the build enforces it).
5. Git: public author identity configured per repository (or per commit), `git gc --prune=now`, first commit
   reviewed (`git show --stat`).
6. Repository settings: private vulnerability reporting enabled (SECURITY.md), branch protection, CI enabled.
7. Privileges ([ELEVATION.md](ELEVATION.md)): no self-elevation and no credential handling in the code (search for
   `RunAs`, `-Verb`, `Get-Credential`, `SecureString`); installer scripts refuse without elevation; the
   [privilege matrix](TESTING.md#privilege-matrix) rows run or listed as `NAO_TESTADO` in the release notes,
   including standard user, elevated administrator and credentials-prompt elevation on Windows 10 and 11 with
   PowerShell 5.1 and 7. A release that changes privilege behaviour needs every row run.
8. Release: tag `v<version>`, attach the zip and `SHA256SUMS.txt`, paste the CHANGELOG section and the known
   limitations from docs/SECURITY-MODEL.md.

## Corrective release 0.1.1 (security fix of 0.1.0)

Built from the `release/0.1.x` line (from tag `v0.1.0`), never from `main` (V0.2). In addition to the checklist above:

1. The release commit is the exact head that CI tested: `release/0.1.x` is advanced to it by fast-forward (no merge
   commit, no squash), because the 0.1.x workflow does not run on pushes to that branch.
2. The package is that run's `release-package` artifact (zip and `SHA256SUMS.txt`), the same archive the six
   `install e2e` jobs checked and installed; its SHA-256 and the run ID are recorded in the pull request. The archive is
   not reproducible byte for byte: if the artifact expired, a maintainer-authorized `workflow_dispatch` on the tagged
   commit rebuilds it and runs the whole e2e again, and the new hash is recorded.
3. `$script:AtmRealDeletionEnabled = $false` in the source, the archive (`Build-Release.ps1` refuses otherwise) and the
   installation (e2e `shipped-release-gate`); `$script:AtmVersion = '0.1.1'`.
4. Tag `v0.1.1` on that commit, GitHub Release with the zip, `SHA256SUMS.txt` and the 0.1.1 release notes, and the
   security advisories for F-01 and F-02 published the same day, naming 0.1.1 as the patched version. Each of these
   steps needs the maintainer's explicit authorization.
