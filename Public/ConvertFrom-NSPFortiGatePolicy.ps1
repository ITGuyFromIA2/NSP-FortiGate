function ConvertFrom-NSPFortiGatePolicy {
    <#
    .SYNOPSIS
        Flattens 'config firewall policy' into one CSV-ready row per policy.
    .DESCRIPTION
        Sequence is the order in the capture, which is the evaluation order;
        PolicyId is the edit number. Status, Action, Nat, UtmStatus, and
        LogTraffic are filled with FortiOS defaults when 'show' omitted them
        (use -NoDefaults to leave them blank). Settings without a named
        column follow under their FortiOS names. For references resolved to
        addresses, ports, and groups, use Get-NSPFortiGatePolicyAccess.
    .PARAMETER Path
        One or more capture files, parsed together.
    .PARAMETER InputObject
        CLI text from the pipeline, for example Get-Clipboard.
    .PARAMETER Delimiter
        Joins multiple values in one cell. Use "`n" for line breaks in Excel.
    .EXAMPLE
        ConvertFrom-NSPFortiGatePolicy -Path .\policies.txt | Export-Csv .\policies.csv -NoTypeInformation
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][ValidateNotNullOrEmpty()][string[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Text')][AllowEmptyString()][string[]]$InputObject,
        [ValidateNotNull()][string]$Delimiter = '; ',
        [switch]$IncludeSecrets,
        [switch]$NoDefaults
    )

    begin { $buffer = [System.Collections.Generic.List[string]]::new() }
    process {
        foreach ($text in $InputObject) { $buffer.AddRange([string[]]($text -split '\r?\n')) }
    }
    end {
        $options = @{ Section = 'firewall policy'; Delimiter = $Delimiter; IncludeSecrets = $IncludeSecrets; NoDefaults = $NoDefaults }
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            ConvertFrom-NSPFortiGateSection -Path $Path @options
        } else {
            , $buffer.ToArray() | ConvertFrom-NSPFortiGateSection @options
        }
    }
}
