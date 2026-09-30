function Format-NSPFortiGateValue {
    <#
    .SYNOPSIS
        Joins a setting's values for CSV output, redacting secrets.
    .DESCRIPTION
        A value is redacted when its key names a password, secret, or key, or
        when FortiOS stored it encrypted (first word ENC).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Key,
        [AllowNull()][AllowEmptyCollection()][string[]]$Value,
        [string]$Delimiter = '; ',
        [switch]$IncludeSecrets
    )

    if ($null -eq $Value -or $Value.Count -eq 0) { return '' }
    $secretKey = '(?i)^(passwd|password|psksecret|secret|private-key|ppk-secret|key|.+-(passwd|password|secret|psk|key))$'
    if (-not $IncludeSecrets -and ($Key -match $secretKey -or $Value[0] -ceq 'ENC')) { return '<redacted>' }
    $Value -join $Delimiter
}
