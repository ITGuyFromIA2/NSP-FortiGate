function New-NSPFortiGatePolicyCli {
    <#
    .SYNOPSIS
        One 'config firewall policy' entry (edit 0 ... next) letting a dial-up VPN reach an internal
        destination, or with -Reverse the mirror policy from the internal side back to the tunnel.
    .DESCRIPTION
        Forward: srcintf the tunnel, srcaddr -TunnelAddress (the client address range), dstintf the
        internal interface, dstaddr -DestinationAddress, and 'set groups' when -UserGroup is given.
        Reverse: the interfaces and addresses swapped, the name prefixed 'REV-', and never a
        'set groups' (only VPN-to-LAN policies are scoped by user group).

        'edit 0' lets FortiOS pick the next free policy ID. Security profiles are set only when given;
        'set utm-status enable' comes with the first one. Returns the entry only, so several can share
        one 'config firewall policy' ... 'end'. Lines end in LF.
    .PARAMETER Name
        The policy's name.
    .PARAMETER TunnelInterface
        The IPsec phase1 interface.
    .PARAMETER InternalInterface
        The internal-side interface.
    .PARAMETER TunnelAddress
        The address object for the VPN clients' address range.
    .PARAMETER DestinationAddress
        The internal address or address group.
    .PARAMETER Service
        Service or service-group names.
    .PARAMETER UserGroup
        FortiGate user group(s) the forward policy is limited to.
    .PARAMETER Disabled
        Create the policy disabled.
    .PARAMETER Reverse
        The internal-to-tunnel mirror.
    .PARAMETER SslSshProfile
        SSL/SSH inspection profile.
    .PARAMETER AntivirusProfile
        Antivirus profile.
    .PARAMETER WebFilterProfile
        Web filter profile.
    .PARAMETER DnsFilterProfile
        DNS filter profile.
    .EXAMPLE
        New-NSPFortiGatePolicyCli -Name 'Contoso-SMB' -TunnelInterface 'IKEv2_Staff' -InternalInterface 'internal' `
            -TunnelAddress 'IKEv2_Staff_range' -DestinationAddress 'VPN_FileServers' -Service 'SMB' -UserGroup 'VPN_Staff'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns CLI text; changes nothing.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$TunnelInterface,
        [Parameter(Mandatory)][string]$InternalInterface,
        [Parameter(Mandatory)][string]$TunnelAddress,
        [Parameter(Mandatory)][string]$DestinationAddress,
        [Parameter(Mandatory)][string[]]$Service,
        [string[]]$UserGroup,
        [switch]$Disabled,
        [switch]$Reverse,
        [string]$SslSshProfile,
        [string]$AntivirusProfile,
        [string]$WebFilterProfile,
        [string]$DnsFilterProfile
    )
    $q = { param([string[]]$Names) (@($Names | Where-Object { $_ } | ForEach-Object { ConvertTo-NSPFortiGateCliName $_ }) -join ' ') }
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('edit 0')
    if ($Reverse) {
        $lines.Add("    set name $(ConvertTo-NSPFortiGateCliName "REV-$Name")")
        $lines.Add("    set srcintf $(ConvertTo-NSPFortiGateCliName $InternalInterface)")
        $lines.Add("    set dstintf $(ConvertTo-NSPFortiGateCliName $TunnelInterface)")
    } else {
        $lines.Add("    set name $(ConvertTo-NSPFortiGateCliName $Name)")
        $lines.Add("    set srcintf $(ConvertTo-NSPFortiGateCliName $TunnelInterface)")
        $lines.Add("    set dstintf $(ConvertTo-NSPFortiGateCliName $InternalInterface)")
    }
    $lines.Add('    set action accept')
    if ($Reverse) {
        $lines.Add("    set srcaddr $(ConvertTo-NSPFortiGateCliName $DestinationAddress)")
        $lines.Add("    set dstaddr $(ConvertTo-NSPFortiGateCliName $TunnelAddress)")
    } else {
        $lines.Add("    set srcaddr $(ConvertTo-NSPFortiGateCliName $TunnelAddress)")
        $lines.Add("    set dstaddr $(ConvertTo-NSPFortiGateCliName $DestinationAddress)")
    }
    $lines.Add('    set schedule "always"')
    $lines.Add("    set service $(& $q $Service)")
    if ($Disabled) { $lines.Add('    set status disable') }
    $profiles = [ordered]@{ 'ssl-ssh-profile' = $SslSshProfile; 'av-profile' = $AntivirusProfile; 'webfilter-profile' = $WebFilterProfile; 'dnsfilter-profile' = $DnsFilterProfile }
    $utm = $false
    foreach ($key in $profiles.Keys) {
        if ([string]::IsNullOrWhiteSpace($profiles[$key])) { continue }
        if (-not $utm) { $lines.Add('    set utm-status enable'); $utm = $true }
        $lines.Add("    set $key $(ConvertTo-NSPFortiGateCliName $profiles[$key])")
    }
    $groups = & $q $UserGroup
    if (-not $Reverse -and $groups) { $lines.Add("    set groups $groups") }
    $lines.Add('next')
    $lines -join "`n"
}
