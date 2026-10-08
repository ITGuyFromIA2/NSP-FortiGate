function ConvertFrom-NSPFortiGateSection {
    <#
    .SYNOPSIS
        Flattens one FortiOS config section into CSV-ready rows.
    .DESCRIPTION
        Emits one row per entry of the named section (for example
        'firewall address' or 'user group'). Known sections get friendly
        columns and filled-in defaults; every other setting follows under its
        FortiOS name, so nothing is dropped. Multi-value settings are joined
        with -Delimiter. Passwords, pre-shared keys, and ENC values are
        redacted unless -IncludeSecrets is set.

        With -UsedByPolicy, the input must also include the firewall policies,
        and only objects they reference (directly, through nested groups, or
        through the tunnel and user groups they name) are returned.
    .PARAMETER Path
        One or more capture files, parsed together.
    .PARAMETER InputObject
        CLI text from the pipeline, for example Get-Clipboard.
    .PARAMETER Section
        Config path as written after 'config', such as 'firewall service group'.
    .PARAMETER Delimiter
        Joins multiple values in one cell. Use "`n" for line breaks in Excel.
    .PARAMETER NoDefaults
        Leave settings that 'show' omitted blank instead of filling the FortiOS default.
    .EXAMPLE
        ConvertFrom-NSPFortiGateSection -Path .\groups.txt -Section 'user group' | Export-Csv .\groups.csv -NoTypeInformation
    .EXAMPLE
        ConvertFrom-NSPFortiGateSection -Path .\policies.txt, .\services.txt -Section 'firewall service custom' -UsedByPolicy
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][ValidateNotNullOrEmpty()][string[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Text')][AllowEmptyString()][string[]]$InputObject,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Section,
        [ValidateNotNull()][string]$Delimiter = '; ',
        [switch]$UsedByPolicy,
        [switch]$IncludeSecrets,
        [switch]$NoDefaults
    )

    begin { $buffer = [System.Collections.Generic.List[string]]::new() }
    process {
        foreach ($text in $InputObject) { $buffer.AddRange([string[]]($text -split '\r?\n')) }
    }
    end {
        $tree = Read-NSPFortiGateInput -Path $Path -Line $buffer.ToArray()
        $found = @(Find-NSPFortiGateSection -Section $tree -Pattern ([WildcardPattern]::Escape($Section.Trim())))
        if ($found.Count -eq 0) {
            Write-Warning "No 'config $Section' block found in the input."
            return
        }
        $include = $null
        if ($UsedByPolicy) {
            $analysis = Get-NSPFortiGatePolicyAnalysis -Tree $tree -Delimiter $Delimiter
            if ($analysis.PolicyCount -eq 0) { throw '-UsedByPolicy needs the firewall policy capture in the input as well.' }
            $include = $analysis.Used
        }
        ConvertTo-NSPFortiGateRow -Section $found -Delimiter $Delimiter -IncludeSecrets:$IncludeSecrets -NoDefaults:$NoDefaults -Include $include
    }
}
