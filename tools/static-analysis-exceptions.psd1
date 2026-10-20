# Reviewed exceptions for tools/Invoke-AtmStaticAnalysis.ps1. Each entry removes findings of ONE rule, only in the
# listed files and, when 'Match' is given, only when the finding message matches that regular expression.
# Excepted findings are still counted and listed in the report (never hidden); an entry that matches nothing is
# reported as stale. Triage: docs/STATIC-ANALYSIS.md.
@{
    Exceptions = @(
        @{
            Rule          = 'PSUseCompatibleCommands'
            Files         = @('src/lib/Tui.ps1')
            Match         = "^The command 'Clear-Host' "
            Justification = 'Clear-Host is a built-in function (not a cmdlet) in Windows PowerShell 5.1, so the cmdlet profile does not list it. The TUI runs on 5.1 in the test suite.'
        }
        @{
            Rule          = 'PSAvoidUsingWriteHost'
            Files         = @('src/agent-temp.ps1', 'src/lib/Report.ps1', 'src/lib/Tui.ps1',
                              'install/Install-AgentTempManager.ps1', 'install/Uninstall-AgentTempManager.ps1', 'install/Restore-AgentTempManagerPrevious.ps1',
                              'tools/Build-Release.ps1', 'tools/Invoke-AtmStaticAnalysis.ps1', 'tools/clean-env/New-CleanEnvSandbox.ps1',
                              'tests/Run-Tests.ps1', 'tests/Get-TempSnapshot.ps1')
            Justification = 'Interactive console presentation (coloured output) by design. The engines, providers, catalog and installer library stay under this rule.'
        }
        @{
            Rule          = 'PSAvoidUsingPositionalParameters'
            Files         = @('src/lib/Tui.ps1')
            Match         = "^Cmdlet '(Limit-AtmText|New-AtmSeg|Format-AtmTuiBar)' "
            Justification = 'Small internal rendering helpers called in dense frame-building expressions.'
        }
        @{
            Rule          = 'PSAvoidUsingPositionalParameters'
            Files         = @('install/InstallCommon.ps1')
            Match         = "^Cmdlet 'Get-AtmText' "
            Justification = 'Get-AtmText takes a variable number of format arguments; they cannot be named.'
        }
        @{
            Rule          = 'PSAvoidUsingPositionalParameters'
            Files         = @('tests/Run-Tests.ps1')
            Match         = "^Cmdlet '(Assert-Eq|Test-Case|New-IdCommit)' "
            Justification = 'Test harness vocabulary (assertions, case declarations), positional for readability.'
        }
        @{
            Rule          = 'PSReviewUnusedParameter'
            Files         = @('src/lib/Report.ps1')
            Match         = "'Inventory'"
            Justification = 'Show-AtmCleanPlan implements the plan presenter contract: the clean engine always passes (verified, rejected, inventory).'
        }
        @{
            Rule          = 'PSReviewUnusedParameter'
            Files         = @('src/lib/Tui.ps1')
            Match         = "'(G|Width|Height)'"
            Justification = 'Read from nested script blocks (Format-AtmTuiTable -G, Get-AtmTuiTextLines -Width, Start-AtmTui -Width/-Height), which the analyser does not follow.'
        }
        @{
            Rule          = 'PSReviewUnusedParameter'
            Files         = @('tests/Run-Tests.ps1')
            Match         = "'(x|p|ProfilePath)'"
            Justification = 'Test stubs that must match a callback signature (confirmation reader, line reader, provider GetProjectKey).'
        }
        @{
            Rule          = 'PSUseShouldProcessForStateChangingFunctions'
            Files         = @('src/lib/Engine.Audit.ps1', 'src/lib/Report.ps1', 'src/lib/Tui.ps1', 'src/lib/I18n.ps1')
            Match         = "'(New-AtmPartition|Set-AtmClassification|New-AtmRow|New-AtmSeg|Start-AtmTui|Set-AtmLanguage)'"
            Justification = 'In-memory constructors, in-process state (language, classification) and the TUI loop: nothing on the system changes.'
        }
        @{
            Rule          = 'PSUseShouldProcessForStateChangingFunctions'
            Files         = @('tests/Run-Tests.ps1')
            Justification = 'Test helpers acting only inside the suite sandbox.'
        }
    )
    # Rules whose findings make -Mode Enforce fail: security, compatibility, and the rules brought to zero by R1-R3.
    EnforcedRules = @(
        'PSAvoidUsingInvokeExpression', 'PSAvoidUsingPlainTextForPassword', 'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUsePSCredentialType', 'PSAvoidUsingUsernameAndPasswordParams', 'PSAvoidUsingComputerNameHardcoded',
        'PSAvoidUsingBrokenHashAlgorithms', 'PSAvoidUsingAllowUnencryptedAuthentication',
        'PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes',
        'PSAvoidAssignmentToAutomaticVariable', 'PSAvoidUsingEmptyCatchBlock', 'PSUseDeclaredVarsMoreThanAssignments'
    )
}
