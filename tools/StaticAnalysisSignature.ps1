# Signature policy for the code files of the pinned PSScriptAnalyzer package (dot-sourced by
# tools/Invoke-AtmStaticAnalysis.ps1 and by the test suite). The package SHA-512 is verified before this runs.
Set-StrictMode -Version 2.0

$script:AtmAnalyzerAllowedSigners = @('Microsoft Corporation', 'Microsoft 3rd Party Application Component', 'Json.NET (.NET Foundation)')

# Reviewed exceptions for files whose signature Windows resolves through one of its own catalogs instead of the
# file's embedded Authenticode signature (newer GitHub runner images ship a catalog that lists the same file hash).
# Each entry matches ONE exact file of the pinned package by relative path AND SHA-256, and only when the catalog
# signature is valid, signed by the exact signer below, and the file still embeds the certificate of an allowed
# signer. The embedded certificate is only extracted, not validated: integrity rests on the package SHA-512, the
# per-file SHA-256 below and the valid Windows catalog signature. A new package version changes the hash and voids
# the entry.
$script:AtmAnalyzerSignatureExceptions = @(
    @{
        Path           = 'Newtonsoft.Json.dll'
        Sha256         = '99C6184C081FBE1B965C168D109C0112F3F2AA1E97D86601411773C34D3CE6A3'
        SignatureType  = 'Catalog'
        Signer         = 'Microsoft Windows'
        EmbeddedSigner = 'Json.NET (.NET Foundation)'
        Justification  = 'Newtonsoft.Json 13.0.4 of PSScriptAnalyzer 1.25.0: on runner image 20261015 Windows resolves it through a Windows catalog (Microsoft Windows); its embedded signature is Json.NET (.NET Foundation).'
    }
)

function Get-AtmAnalyzerSignatureInfo {
    # Collects what the policy needs about one file. Never decides.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$RelativePath)
    $simple = [Security.Cryptography.X509Certificates.X509NameType]::SimpleName
    $s = Get-AuthenticodeSignature -LiteralPath $Path
    $signer = $(if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo($simple, $false) } else { '' })
    $type = $(if ($s.PSObject.Properties['SignatureType']) { [string]$s.SignatureType } else { '' })
    # Fail-closed: a file without an embedded certificate (or unreadable) has no embedded signer.
    try { $embedded = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 ([Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($Path))).GetNameInfo($simple, $false) } catch { $embedded = '' }
    return [pscustomobject]@{
        RelativePath   = $RelativePath
        Sha256         = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        Status         = [string]$s.Status
        SignatureType  = $type
        Signer         = $signer
        EmbeddedSigner = $embedded
    }
}

function Test-AtmAnalyzerSignature {
    # Decision on collected facts. Returns Accepted, the exception used (or $null) and the reason.
    param([Parameter(Mandatory)]$Facts)
    if ($Facts.Status -ceq 'Valid' -and $script:AtmAnalyzerAllowedSigners -ccontains $Facts.Signer) {
        return [pscustomobject]@{ Accepted = $true; Exception = $null; Reason = 'allowed signer' }
    }
    foreach ($e in $script:AtmAnalyzerSignatureExceptions) {
        if ($Facts.RelativePath -cne $e.Path) { continue }
        if ($Facts.Sha256 -cne $e.Sha256) { return [pscustomobject]@{ Accepted = $false; Exception = $null; Reason = 'excecao: SHA-256 difere do fixado' } }
        if ($Facts.Status -cne 'Valid') { return [pscustomobject]@{ Accepted = $false; Exception = $null; Reason = "excecao: status $($Facts.Status)" } }
        if ($Facts.SignatureType -cne $e.SignatureType) { return [pscustomobject]@{ Accepted = $false; Exception = $null; Reason = "excecao: tipo de assinatura '$($Facts.SignatureType)'" } }
        if ($Facts.Signer -cne $e.Signer) { return [pscustomobject]@{ Accepted = $false; Exception = $null; Reason = "excecao: signatario '$($Facts.Signer)'" } }
        if ($Facts.EmbeddedSigner -cne $e.EmbeddedSigner) { return [pscustomobject]@{ Accepted = $false; Exception = $null; Reason = "excecao: certificado embutido '$($Facts.EmbeddedSigner)'" } }
        return [pscustomobject]@{ Accepted = $true; Exception = $e.Path; Reason = 'excecao revisada' }
    }
    return [pscustomobject]@{ Accepted = $false; Exception = $null; Reason = "status $($Facts.Status), signatario '$($Facts.Signer)'" }
}
