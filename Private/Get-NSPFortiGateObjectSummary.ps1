function Get-NSPFortiGateObjectSummary {
    <#
    .SYNOPSIS
        One-line description of what an address, VIP, or service matches.
    .DESCRIPTION
        Addresses become CIDR, ranges, FQDNs, or countries ("10.0.1.0/24",
        a single host drops /32). Services become protocol/port lists
        ("TCP/53, UDP/53"); the source-port half of dst:src ranges is left
        out. Returns '' for sections it does not describe.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Settings', Justification = 'Read inside the $get script block.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Settings
    )

    $get = {
        param([string]$Key)
        if ($Settings.Contains($Key)) { @($Settings[$Key]) } else { @() }
    }
    $one = {
        param([string]$Key, [string]$Default = '')
        $value = & $get $Key
        if ($value.Count) { $value -join ' ' } else { $Default }
    }
    $toCidr = {
        param([string[]]$Subnet)
        if ($Subnet.Count -eq 1 -and $Subnet[0] -match '/') { return $Subnet[0] }
        if ($Subnet.Count -lt 2) { return ($Subnet -join ' ') }
        $bits = 0
        foreach ($octet in $Subnet[1].Split('.')) {
            $number = 0
            if (-not [int]::TryParse($octet, [ref]$number)) { return ($Subnet -join ' ') }
            $bits += ([Convert]::ToString($number, 2).ToCharArray() | Where-Object { $_ -eq '1' }).Count
        }
        if ($bits -eq 32) { $Subnet[0] } else { "$($Subnet[0])/$bits" }
    }

    switch ($Path) {
        { $_ -eq 'firewall address' -or $_ -eq 'firewall address6' } {
            $type = & $one 'type' 'ipmask'
            switch ($type) {
                'ipmask' {
                    if ($Path -eq 'firewall address6') { return (& $one 'ip6' '::/0') }
                    $subnet = & $get 'subnet'
                    if ($subnet.Count) { return (& $toCidr $subnet) } else { return '0.0.0.0/0' }
                }
                'interface-subnet' { return (& $toCidr (& $get 'subnet')) }
                'iprange' { return "$(& $one 'start-ip')-$(& $one 'end-ip')" }
                'fqdn' { return (& $one 'fqdn') }
                'geography' { return "country $(& $one 'country')" }
                'wildcard' { return "wildcard $(& $one 'wildcard')" }
                'wildcard-fqdn' { return (& $one 'wildcard-fqdn') }
                'mac' {
                    $macs = @(& $get 'macaddr')
                    if ($macs.Count -gt 3) { return "mac ($($macs.Count) addresses)" } else { return "mac $($macs -join ' ')" }
                }
                'dynamic' { return (@('dynamic', (& $one 'sub-type')) | Where-Object { $_ }) -join ' ' }
                default { return $type }
            }
        }
        { $_ -eq 'firewall vip' -or $_ -eq 'firewall vip6' } {
            $text = "$(& $one 'extip') -> $(& $one 'mappedip')"
            if ((& $one 'portforward') -eq 'enable') {
                $text += " $((& $one 'protocol' 'tcp').ToUpperInvariant())/$(& $one 'extport')->$(& $one 'mappedport')"
            }
            return $text
        }
        'vpn ipsec phase1-interface' {
            $type = & $one 'type' 'static'
            $text = "IKEv$(& $one 'ike-version' '1') " + $(if ($type -eq 'dynamic') { 'dial-up' } else { "$type to $(& $one 'remote-gw')" })
            $text += " on $(& $one 'interface')"
            $pool = & $one 'ipv4-name'
            if (-not $pool -and (& $one 'ipv4-start-ip')) { $pool = "$(& $one 'ipv4-start-ip')-$(& $one 'ipv4-end-ip')" }
            if ($pool) { $text += ", pool $pool" }
            $split = & $one 'ipv4-split-include'
            if ($split) { $text += ", split $split" }
            $peers = @((& $one 'peergrp'), (& $one 'peer'), (& $one 'usrgrp'), (& $one 'authusrgrp')) | Where-Object { $_ }
            if ($peers) { $text += ", peers $($peers -join ' ')" }
            return $text
        }
        'user peer' {
            $parts = @(
                if (& $one 'ca') { "CA $(& $one 'ca')" }
                if (& $one 'subject') { "subject $(& $one 'subject')" }
                if (& $one 'cn') { "CN $(& $one 'cn')" }
                if (& $one 'mfa-server') { "MFA $(& $one 'mfa-server')" }
            )
            return ($parts -join ', ')
        }
        'firewall service custom' {
            $protocol = & $one 'protocol' 'TCP/UDP/SCTP'
            $parts = [System.Collections.Generic.List[string]]::new()
            switch -Regex ($protocol) {
                '^ICMP6?$' {
                    $text = $protocol
                    $type = & $one 'icmptype'
                    if ($type) { $text += " type $type" }
                    $code = & $one 'icmpcode'
                    if ($code) { $text += " code $code" }
                    $parts.Add($text)
                }
                '^IP$' {
                    $number = & $one 'protocol-number' '0'
                    $parts.Add($(if ($number -eq '0') { 'IP/any' } else { "IP/$number" }))
                }
                '^TCP' {
                    foreach ($pair in @(@('tcp-portrange', 'TCP'), @('udp-portrange', 'UDP'), @('udplite-portrange', 'UDP-Lite'), @('sctp-portrange', 'SCTP'))) {
                        foreach ($range in (& $get $pair[0])) { $parts.Add("$($pair[1])/$($range.Split(':')[0])") }
                    }
                }
                default { $parts.Add($protocol) }
            }
            $text = $parts -join ', '
            # show full-configuration prints the 0.0.0.0 "any destination" default.
            $target = @((& $one 'iprange'), (& $one 'fqdn')) | Where-Object { $_ -and $_ -ne '0.0.0.0' }
            if ($target) { $text += " to $($target -join ' ')" }
            return $text
        }
        default { return '' }
    }
}
