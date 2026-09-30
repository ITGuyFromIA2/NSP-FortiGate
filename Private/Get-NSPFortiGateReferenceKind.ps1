function Get-NSPFortiGateReferenceKind {
    <#
    .SYNOPSIS
        Where each kind of policy reference can be defined, and what it uses.
    .DESCRIPTION
        Sections lists, in lookup order, the config paths a name of that kind
        may live in. Builtin names need no definition; kinds with
        ReportMissing = $false (interfaces: port1, wan1 are rarely captured)
        are never reported as unresolved.

        Groups are expanded into their leaves in the policy report. Related
        references are only walked, so the objects they name count as used
        (a tunnel's client pool, a user group's RADIUS server).
    #>
    [CmdletBinding()]
    param()

    @{
        Address = @{
            Sections = @('firewall address', 'firewall addrgrp', 'firewall address6', 'firewall addrgrp6', 'firewall vip', 'firewall vipgrp', 'firewall vip6')
            Builtin = @('all', 'none')
            ReportMissing = $true
        }
        Service = @{
            Sections = @('firewall service custom', 'firewall service group')
            Builtin = @('ALL')
            ReportMissing = $true
        }
        User = @{
            Sections = @('user group', 'user local', 'user radius', 'user ldap', 'user saml', 'user tacacs+', 'user fsso', 'user peergrp', 'user peer')
            Builtin = @()
            ReportMissing = $true
        }
        Interface = @{
            Sections = @('vpn ipsec phase1-interface', 'system zone', 'system interface')
            Builtin = @('any')
            ReportMissing = $false
        }
        Groups = @{
            'firewall addrgrp' = [ordered]@{ member = 'Address'; 'exclude-member' = 'Address' }
            'firewall addrgrp6' = [ordered]@{ member = 'Address'; 'exclude-member' = 'Address' }
            'firewall vipgrp' = [ordered]@{ member = 'Address' }
            'firewall service group' = [ordered]@{ member = 'Service' }
        }
        Related = @{
            'user group' = [ordered]@{ member = 'User' }
            'user peergrp' = [ordered]@{ member = 'User' }
            'user peer' = [ordered]@{ 'mfa-server' = 'User' }
            'system zone' = [ordered]@{ interface = 'Interface' }
            'vpn ipsec phase1-interface' = [ordered]@{
                'ipv4-name' = 'Address'; 'ipv4-split-include' = 'Address'; 'ipv4-split-exclude' = 'Address'
                'ipv6-name' = 'Address'; 'ipv6-split-include' = 'Address'
                peergrp = 'User'; peer = 'User'; usrgrp = 'User'; authusrgrp = 'User'
            }
        }
    }
}
