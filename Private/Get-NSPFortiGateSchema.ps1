function Get-NSPFortiGateSchema {
    <#
    .SYNOPSIS
        Column layouts for the FortiOS sections with dedicated CSV output.
    .DESCRIPTION
        Keyed by config path. IdColumn names the edit key. Columns maps a CSV
        column to a FortiOS setting, in output order. Defaults fill settings
        that plain 'show' omits because they hold the factory value.
        A column mapped to $null is computed by Get-NSPFortiGateObjectSummary
        (an address as CIDR, a service as TCP/443).
        ChildColumns renders a nested config block (such as a user group's
        'config match') by joining the named keys of each nested entry.

        Settings not listed here still reach the CSV under their FortiOS name,
        so adding a section is optional polish, never required for coverage.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    [ordered]@{
        'firewall policy' = @{
            IdColumn = 'PolicyId'
            Columns = [ordered]@{
                Name = 'name'; Status = 'status'; Action = 'action'
                SrcIntf = 'srcintf'; DstIntf = 'dstintf'; SrcAddr = 'srcaddr'; DstAddr = 'dstaddr'
                Service = 'service'; Schedule = 'schedule'; Users = 'users'; Groups = 'groups'
                Nat = 'nat'; IpPool = 'ippool'; PoolName = 'poolname'
                UtmStatus = 'utm-status'; InspectionMode = 'inspection-mode'; SslSshProfile = 'ssl-ssh-profile'
                AvProfile = 'av-profile'; WebFilterProfile = 'webfilter-profile'; DnsFilterProfile = 'dnsfilter-profile'
                ApplicationList = 'application-list'; IpsSensor = 'ips-sensor'
                LogTraffic = 'logtraffic'; Comments = 'comments'; Uuid = 'uuid'
            }
            Defaults = @{ status = 'enable'; action = 'deny'; nat = 'disable'; 'utm-status' = 'disable'; logtraffic = 'utm' }
        }
        'firewall address' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Summary = $null; Type = 'type'; SubType = 'sub-type'; Subnet = 'subnet'; StartIp = 'start-ip'; EndIp = 'end-ip'
                Fqdn = 'fqdn'; Country = 'country'; Wildcard = 'wildcard'; MacAddr = 'macaddr'
                Interface = 'interface'; AssociatedInterface = 'associated-interface'; Comment = 'comment'; Uuid = 'uuid'
            }
            Defaults = @{ type = 'ipmask' }
        }
        'firewall addrgrp' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{ Members = 'member'; Exclude = 'exclude'; ExcludeMembers = 'exclude-member'; Comment = 'comment'; Uuid = 'uuid' }
            Defaults = @{ exclude = 'disable' }
        }
        'firewall service custom' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Summary = $null; Protocol = 'protocol'; TcpPortRange = 'tcp-portrange'; UdpPortRange = 'udp-portrange'
                SctpPortRange = 'sctp-portrange'; IcmpType = 'icmptype'; IcmpCode = 'icmpcode'; ProtocolNumber = 'protocol-number'
                IpRange = 'iprange'; Fqdn = 'fqdn'; Category = 'category'; Comment = 'comment'; Uuid = 'uuid'
            }
            Defaults = @{ protocol = 'TCP/UDP/SCTP' }
        }
        'firewall service group' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{ Members = 'member'; Comment = 'comment'; Uuid = 'uuid' }
            Defaults = @{}
        }
        'vpn ipsec phase1-interface' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Summary = $null; Type = 'type'; Interface = 'interface'; IkeVersion = 'ike-version'
                RemoteGw = 'remote-gw'; LocalGw = 'local-gw'; AuthMethod = 'authmethod'; PeerType = 'peertype'
                PeerGroup = 'peergrp'; Certificate = 'certificate'; Eap = 'eap'; ModeCfg = 'mode-cfg'
                AssignIpFrom = 'assign-ip-from'; ClientRange = 'ipv4-name'; StartIp = 'ipv4-start-ip'; EndIp = 'ipv4-end-ip'
                Netmask = 'ipv4-netmask'; SplitInclude = 'ipv4-split-include'; DnsServer1 = 'ipv4-dns-server1'
                DnsServer2 = 'ipv4-dns-server2'; Proposal = 'proposal'; DhGroup = 'dhgrp'; Comments = 'comments'
            }
            Defaults = @{ type = 'static'; 'ike-version' = '1'; authmethod = 'psk' }
        }
        'vpn ipsec phase2-interface' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Phase1Name = 'phase1name'; Proposal = 'proposal'; DhGroup = 'dhgrp'; Pfs = 'pfs'
                SrcName = 'src-name'; SrcSubnet = 'src-subnet'; DstName = 'dst-name'; DstSubnet = 'dst-subnet'
                KeyLifeSeconds = 'keylifeseconds'; Comments = 'comments'
            }
            Defaults = @{ pfs = 'enable' }
        }
        'user peergrp' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{ Members = 'member' }
            Defaults = @{}
        }
        'user peer' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Summary = $null; Ca = 'ca'; Subject = 'subject'; Cn = 'cn'; CnType = 'cn-type'
                MfaMode = 'mfa-mode'; MfaServer = 'mfa-server'; OcspOverrideServer = 'ocsp-override-server'
            }
            Defaults = @{}
        }
        'user local' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Status = 'status'; Type = 'type'; LdapServer = 'ldap-server'; RadiusServer = 'radius-server'
                TwoFactor = 'two-factor'; FortiToken = 'fortitoken'; EmailTo = 'email-to'
            }
            Defaults = @{ status = 'enable'; type = 'password'; 'two-factor' = 'disable' }
        }
        'user group' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{ GroupType = 'group-type'; Members = 'member' }
            ChildColumns = [ordered]@{ Match = @{ Section = 'match'; Keys = @('server-name', 'group-name'); Separator = ': ' } }
            Defaults = @{ 'group-type' = 'firewall' }
        }
        'user radius' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Server = 'server'; SecondaryServer = 'secondary-server'; TertiaryServer = 'tertiary-server'
                AuthType = 'auth-type'; NasIp = 'nas-ip'; SourceIp = 'source-ip'; Timeout = 'timeout'
            }
            Defaults = @{ 'auth-type' = 'auto'; timeout = '5' }
        }
        'user ldap' = @{
            IdColumn = 'Name'
            Columns = [ordered]@{
                Server = 'server'; SecondaryServer = 'secondary-server'; Port = 'port'; Secure = 'secure'
                Cnid = 'cnid'; Dn = 'dn'; Type = 'type'; Username = 'username'; SourceIp = 'source-ip'
            }
            Defaults = @{ port = '389'; secure = 'disable'; cnid = 'cn'; type = 'simple' }
        }
    }
}
