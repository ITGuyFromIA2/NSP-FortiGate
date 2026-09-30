<#
.SYNOPSIS
    Publishes NSP.FortiGate to the PowerShell Gallery (or another repository).

.DESCRIPTION
    Publish-PSResource -Path expects the source folder's name to match the module name
    (the manifest's own basename). This repo's working directory is NSP-FortiGate (hyphen -
    matches the GitHub naming convention every NSP-* repo uses); the module's actual PowerShell
    identity is NSP.FortiGate (dot - matches standard module naming, e.g. Az.Accounts). That
    mismatch is why this script stages the package under an `NSP.FortiGate` folder.

    This script stages a copy under the correct name in a temp directory and publishes from
    there. Only runtime/user-facing content is staged. Tests, tools, and local repo
    settings are not included in the Gallery package.

.PARAMETER Repository
    The registered PSRepository to publish to. Defaults to 'PSGallery'. Point this at a local
    test repository (see about_Repositories) to dry-run the staging + publish path without
    touching the real Gallery.

.PARAMETER SecretName
    NSP secret holding the repository API key. Defaults to 'MS.PSGallery.ApiKey'.

.PARAMETER BootstrapManifest
    Optional path to NSP.Bootstrap.psd1 if NSP.Bootstrap is not installed as a module.

.PARAMETER WhatIf
    Stage and validate (Test-ModuleManifest against the staged copy) but skip the actual
    publish call, secret access, and post-publish verification.

.EXAMPLE
    .\tools\Publish-ToGallery.ps1

.EXAMPLE
    .\tools\Publish-ToGallery.ps1 -WhatIf
#>
# Interactive release tool: its progress lines are for the person publishing, not pipeline output.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Repository = 'PSGallery',
    [string]$SecretName = 'MS.PSGallery.ApiKey',
    [string]$BootstrapManifest
)

$ErrorActionPreference = 'Stop'
$repoRoot   = Split-Path -Parent $PSScriptRoot
$moduleName = 'NSP.FortiGate'

$manifestPath = Join-Path $repoRoot "$moduleName.psd1"
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "Manifest not found: $manifestPath" }
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath

# A publish attempt must pass the same parser, behavior, analyzer, and
# public-source checks as a normal repository validation run.
& (Join-Path $PSScriptRoot 'Test-Repo.ps1')

# What actually ships to Install-Module users - runtime code + user-facing docs, not the dev
# tooling (Tests\, tools\, lint settings, AI-agent instructions) that only matters in this repo.
$publishItems = @(
    "$moduleName.psd1"
    "$moduleName.psm1"
    'Public'
    'Private'
    'README.md'
    'LICENSE'
    'CHANGELOG.md'
)
foreach ($item in $publishItems) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $item))) {
        throw "Required package item is missing: $item"
    }
}

$tempBase        = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$stageRoot       = [IO.Path]::GetFullPath((Join-Path $tempBase ('NSPFortiGatePublish_' + [guid]::NewGuid().ToString('N'))))
if (-not $stageRoot.StartsWith(($tempBase + '\'), [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($stageRoot)).StartsWith('NSPFortiGatePublish_')) {
    throw 'Staging directory is outside the expected temporary directory.'
}
$stageModuleDir  = Join-Path $stageRoot $moduleName
# -WhatIf:$false on every staging operation below: this script's own -WhatIf/-Confirm would
# otherwise auto-propagate to New-Item/Copy-Item (they support ShouldProcess too), which
# would silently skip the staging and validation entirely instead of just skipping the real
# publish. Staging into a throwaway temp dir isn't the operation worth previewing - only the
# actual Publish-Module call, gated below, is.
New-Item -ItemType Directory -Path $stageModuleDir -Force -WhatIf:$false | Out-Null

try {
    foreach ($item in $publishItems) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $item) -Destination (Join-Path $stageModuleDir $item) -Recurse -Force -WhatIf:$false
    }
    Write-Host "Staged $moduleName $($manifest.ModuleVersion) at $stageModuleDir" -ForegroundColor DarkGray

    # Fails loudly here, before anything touches the network, if the staged copy is somehow
    # incomplete or the manifest doesn't parse.
    $null = Test-ModuleManifest -Path (Join-Path $stageModuleDir "$moduleName.psd1") -ErrorAction Stop
    Write-Host "Staged manifest OK." -ForegroundColor DarkGray

    if ($PSCmdlet.ShouldProcess("$moduleName $($manifest.ModuleVersion) -> $Repository", 'Publish')) {
        # Only touches the secret store / network on a real (non -WhatIf) run.
        $psResourceGet = Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending | Select-Object -First 1
        if (-not $psResourceGet) {
            throw 'Microsoft.PowerShell.PSResourceGet is required for a real publish run.'
        }

        if ($BootstrapManifest) {
            if (-not (Test-Path -LiteralPath $BootstrapManifest)) { throw "Bootstrap manifest not found: $BootstrapManifest" }
            Import-Module $BootstrapManifest -Force -ErrorAction Stop
        } else {
            $bootstrapCandidates = @(
                (Join-Path $repoRoot '..\NSP-Bootstrap\NSP.Bootstrap.psd1')
                (Join-Path $repoRoot '..\..\NSP-Bootstrap\NSP.Bootstrap.psd1')
            )
            $localBootstrap = $bootstrapCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            if ($localBootstrap) { Import-Module $localBootstrap -Force -ErrorAction Stop }
            else { Import-Module NSP.Bootstrap -Force -ErrorAction Stop }
        }
        if (-not (Get-Command Get-NSPSecret -ErrorAction SilentlyContinue)) {
            throw 'NSP.Bootstrap did not provide Get-NSPSecret.'
        }
        $apiKey = Get-NSPSecret -Name $SecretName -AsPlainText
        if ([string]::IsNullOrWhiteSpace($apiKey)) { throw "Secret '$SecretName' is empty or missing." }

        Import-Module Microsoft.PowerShell.PSResourceGet -RequiredVersion $psResourceGet.Version -Force -ErrorAction Stop
        Write-Host "Publishing via Microsoft.PowerShell.PSResourceGet $($psResourceGet.Version)..." -ForegroundColor DarkGray
        Publish-PSResource -Path $stageModuleDir -ApiKey $apiKey -Repository $Repository -ErrorAction Stop

        # Trust but verify - the legacy tooling has already been caught reporting success on a
        # run that actually failed. Confirm the version is really there before calling it done.
        Write-Host "Verifying..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
        $found = Find-PSResource -Name $moduleName -Version $manifest.ModuleVersion -Repository $Repository -ErrorAction SilentlyContinue
        if ($found) {
            Write-Host "Confirmed: $moduleName $($manifest.ModuleVersion) is live on $Repository." -ForegroundColor Green
        } else {
            Write-Warning "Publish-PSResource reported success, but Find-PSResource can't see $moduleName $($manifest.ModuleVersion) on $Repository yet. This can be Gallery indexing lag (retry in a minute or two) or a genuine failure - don't assume it worked without checking https://www.powershellgallery.com/packages/$moduleName."
        }
    }
} finally {
    # Real cleanup even under -WhatIf, for the same reason staging above forces -WhatIf:$false -
    # otherwise every -WhatIf run leaves its temp directory behind.
    Remove-Item -LiteralPath $stageRoot -Recurse -Force -WhatIf:$false -ErrorAction SilentlyContinue
}
