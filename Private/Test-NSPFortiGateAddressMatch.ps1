function Test-NSPFortiGateAddressMatch {
    <#
    .SYNOPSIS
        True when an IPv4 address equals an NPS RADIUS client address, or falls inside it when the
        client is a CIDR range. Host names match only when identical.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Ip, [string]$Address)

    if (-not $Ip -or -not $Address) { return $false }
    if ($Address -eq $Ip) { return $true }
    if ($Address -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') { return $false }
    $network = $null
    $candidate = $null
    $bits = [int]$Matches[2]
    if ($bits -gt 32 -or -not [ipaddress]::TryParse($Matches[1], [ref]$network) -or -not [ipaddress]::TryParse($Ip, [ref]$candidate)) { return $false }
    $toNumber = { param($Value) $bytes = $Value.GetAddressBytes(); [Array]::Reverse($bytes); [BitConverter]::ToUInt32($bytes, 0) }
    # 4294967295, not 0xFFFFFFFF: PowerShell reads that hex literal as the Int32 -1.
    $mask = [uint32](([uint64]4294967295 -shl (32 - $bits)) -band [uint64]4294967295)
    ((& $toNumber $candidate) -band $mask) -eq ((& $toNumber $network) -band $mask)
}
