function New-NSPFortiGateAddressGroupCli {
    <#
    .SYNOPSIS
        FortiGate CLI for an address group: one 'config firewall address' object per new member plus
        the 'config firewall addrgrp' that holds them.
    .DESCRIPTION
        Each -Member is an IPv4 address or subnet (no /prefix means a single host, /32), or else an
        FQDN. Object names come from the member itself: 'Subnet_10_0_0_0_24' for a subnet, the FQDN
        as-is for an FQDN, so the CLI reads on its own later.

        -ExistingMemberName adds objects that already exist on the FortiGate to the group without
        defining them again (their real type and value aren't known here).

        A group with no members is still created, empty: FortiOS rejects 'set member' with nothing
        after it, so that line is left out. Lines end in LF.
    .PARAMETER GroupName
        The address group's name.
    .PARAMETER Member
        New members: IPv4 addresses, subnets in CIDR form, or FQDNs.
    .PARAMETER ExistingMemberName
        Names of address or address-group objects already on the FortiGate.
    .EXAMPLE
        New-NSPFortiGateAddressGroupCli -GroupName 'VPN_FileServers' -Member '10.0.0.10', 'files.contoso.com', '10.0.5.0/24'
    .EXAMPLE
        New-NSPFortiGateAddressGroupCli -GroupName 'VPN_App' -ExistingMemberName 'App_Servers' | Set-Clipboard
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns CLI text; changes nothing.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [AllowEmptyCollection()][string[]]$Member = @(),
        [AllowEmptyCollection()][string[]]$ExistingMemberName = @()
    )

    $names = [Collections.Generic.List[string]]::new()
    $objects = [Collections.Generic.List[string]]::new()
    foreach ($entry in $Member) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        if ($entry -match '^(?<addr>\d{1,3}(\.\d{1,3}){3})(?:/(?<cidr>\d{1,2}))?$') {
            $addr = $Matches['addr']
            $cidr = if ($Matches['cidr']) { [int]$Matches['cidr'] } else { 32 }
            $name = "Subnet_$($addr.Replace('.', '_'))_$cidr"
            $objects.Add("    edit `"$name`"`n        set subnet $addr $(ConvertTo-NSPFortiGateSubnetMask -PrefixLength $cidr)`n    next")
        } else {
            $name = $entry.Replace('"', '')
            $objects.Add("    edit `"$name`"`n        set type fqdn`n        set fqdn `"$name`"`n    next")
        }
        $names.Add($name)
    }
    foreach ($existing in $ExistingMemberName) {
        if (-not [string]::IsNullOrWhiteSpace($existing)) { $names.Add($existing.Replace('"', '')) }
    }

    $memberLine = if ($names.Count) { "`n        set member " + (@($names | ForEach-Object { "`"$_`"" }) -join ' ') } else { '' }
    "config firewall address`n$($objects -join "`n")`nend`n`nconfig firewall addrgrp`n    edit `"$GroupName`"$memberLine`n    next`nend"
}
