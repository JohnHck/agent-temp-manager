## Summary

<!-- What does this change and why? -->

## Safety checklist

- [ ] Tests pass on Windows PowerShell 5.1 and PowerShell 7 (`./tests/Run-Tests.ps1`)
- [ ] No change makes the audit or preview write, move or delete anything
- [ ] Real deletion stays disabled (`$script:AtmRealDeletionEnabled = $false`) unless this PR is the reviewed change that enables it
- [ ] Classification stays conservative: on doubt, the path is preserved
- [ ] No personal data (user names, machine names, SIDs, e-mails, real paths, tokens) in code, tests, docs or fixtures
- [ ] User-facing text goes through the catalog (`src/lib/I18n.ps1`) in en-US and pt-BR
