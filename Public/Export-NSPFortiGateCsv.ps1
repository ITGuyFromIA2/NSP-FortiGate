function Export-NSPFortiGateCsv {
    <#
    .SYNOPSIS
        Writes one CSV per FortiOS section, plus a policy access report.
    .DESCRIPTION
        Parses all captures together and writes <Prefix>_<section>.csv for each
        requested section present in them. When firewall policies are present
        it also writes <Prefix>_policy-access.csv (see
        Get-NSPFortiGatePolicyAccess). Returns the files written.

        With -UsedByPolicy, object sections (addresses, services, users and
        groups, RADIUS/LDAP servers, IPsec tunnels, zones) keep only entries
        the policies reference, directly or through nested groups. Other
        sections are written whole.
    .PARAMETER Path
        Capture files, parsed together. Wildcards are accepted.
    .PARAMETER OutputDirectory
        Defaults to the folder of the first capture.
    .PARAMETER Prefix
        File name prefix. Defaults to the capture's name for one file, else 'FortiGate'.
    .PARAMETER Section
        Section paths to write; wildcards allowed. Defaults to every section
        with a named column layout. '*' writes every section found.
    .PARAMETER Delimiter
        Joins multiple values in one cell. Use "`n" for line breaks in Excel.
    .PARAMETER NoDefaults
        Leave settings that 'show' omitted blank instead of filling the FortiOS default.
    .EXAMPLE
        Export-NSPFortiGateCsv -Path .\captures\*.txt -OutputDirectory .\out -Prefix FGT01 -UsedByPolicy
    .EXAMPLE
        Export-NSPFortiGateCsv -Path .\full-config.conf -Section * -OutputDirectory .\dump
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, Position = 0)][ValidateNotNullOrEmpty()][string[]]$Path,
        [string]$OutputDirectory,
        [string]$Prefix,
        [string[]]$Section,
        [ValidateNotNull()][string]$Delimiter = '; ',
        [switch]$UsedByPolicy,
        [switch]$IncludeSecrets,
        [switch]$NoDefaults
    )

    $tree = Read-NSPFortiGateInput -Path $Path
    $first = @(foreach ($item in $Path) { if (Test-Path -LiteralPath $item) { Get-Item -LiteralPath $item } else { Get-Item -Path $item } })
    if (-not $OutputDirectory) { $OutputDirectory = $first[0].DirectoryName }
    if (-not $Prefix) { $Prefix = if ($first.Count -eq 1) { $first[0].BaseName } else { 'FortiGate' } }
    if (-not $Section) { $Section = @((Get-NSPFortiGateSchema).Keys) }
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    $encoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
    $analysis = Get-NSPFortiGatePolicyAnalysis -Tree $tree -Delimiter $Delimiter
    if ($UsedByPolicy -and $analysis.PolicyCount -eq 0) { throw '-UsedByPolicy needs the firewall policy capture among the inputs.' }

    $kinds = Get-NSPFortiGateReferenceKind
    $filtered = @($kinds.Address.Sections + $kinds.Service.Sections + $kinds.User.Sections + $kinds.Interface.Sections + 'vpn ipsec phase2-interface')

    $groups = [ordered]@{}
    foreach ($found in (Find-NSPFortiGateSection -Section $tree -Pattern $Section)) {
        if (-not $groups.Contains($found.Path)) { $groups[$found.Path] = [System.Collections.Generic.List[object]]::new() }
        $groups[$found.Path].Add($found)
    }
    if ($groups.Count -eq 0 -and $analysis.PolicyCount -eq 0) { Write-Warning 'None of the requested sections were found in the input.' }

    $write = {
        param([object[]]$Rows, [string]$Name)
        $file = Join-Path $OutputDirectory ('{0}_{1}.csv' -f $Prefix, ($Name -replace '[^\w.+-]+', '-'))
        $Rows | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding $encoding
        Get-Item -LiteralPath $file
    }

    foreach ($sectionPath in $groups.Keys) {
        $include = if ($UsedByPolicy -and $filtered -contains $sectionPath) { $analysis.Used } else { $null }
        $rows = @(ConvertTo-NSPFortiGateRow -Section $groups[$sectionPath].ToArray() -Delimiter $Delimiter -IncludeSecrets:$IncludeSecrets -NoDefaults:$NoDefaults -Include $include)
        if ($rows.Count -eq 0) { Write-Verbose "No rows for '$sectionPath'; no file written."; continue }
        & $write $rows $sectionPath
    }
    if ($analysis.PolicyCount) { & $write $analysis.Rows 'policy-access' }
}
