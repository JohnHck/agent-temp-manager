# PSScriptAnalyzer settings for tools/Invoke-AtmStaticAnalysis.ps1.
# Phase 1 (informative): every default rule is enabled and nothing is excluded. Findings are triaged in
# docs/STATIC-ANALYSIS.md; a rule is only excluded or suppressed there, one justified case at a time.
@{
    IncludeDefaultRules = $true
    Severity            = @('Error', 'Warning', 'Information')
    Rules               = @{
        # The product targets Windows PowerShell 5.1 and PowerShell 7 on Windows.
        PSUseCompatibleSyntax   = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @(
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'   # Windows 10, PS 5.1
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'    # Windows Server 2019, PS 5.1
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'                            # Windows, PS 7
            )
        }
        PSUseCompatibleTypes    = @{
            Enable         = $true
            TargetProfiles = @(
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
            )
        }
    }
}
