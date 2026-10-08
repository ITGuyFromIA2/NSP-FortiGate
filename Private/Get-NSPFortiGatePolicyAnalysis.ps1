function Get-NSPFortiGatePolicyAnalysis {
    <#
    .SYNOPSIS
        Resolves every firewall policy's references into report rows.
    .DESCRIPTION
        Returns Rows (one per policy, see Get-NSPFortiGatePolicyAccess) and
        Used (object keys of everything the policies reach, directly or
        through groups, tunnels, and user groups). A phase2 counts as used
        when its phase1 does. PolicyCount is 0 when no policy was loaded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Tree,
        [string]$Delimiter = '; '
    )

    $index = Get-NSPFortiGateIndex -Tree $Tree
    $used = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $policies = @(Find-NSPFortiGateSection -Section $Tree -Pattern 'firewall policy')
    $showVdom = @($policies | Where-Object { $_.Vdom }).Count -gt 0

    $label = {
        param($Leaf)
        if ($Leaf.Missing) { return "$($Leaf.Name) (not in input)" }
        $text = $Leaf.Name
        if ($Leaf.Entry) {
            $summary = Get-NSPFortiGateObjectSummary -Path $Leaf.Path -Settings $Leaf.Entry.Settings
            if ($summary) { $text = "$text ($summary)" }
        }
        if ($Leaf.Excluded) { $text = "NOT $text" }
        $text
    }
    $peers = {
        param($Leaves)
        foreach ($leaf in $Leaves) {
            if ($leaf.Path -eq 'user peer') { & $label $leaf }
            if ($leaf.Related) { & $peers $leaf.Related }
        }
    }
    $missing = {
        param($Leaves)
        foreach ($leaf in $Leaves) {
            if ($leaf.Missing) { "$($leaf.Kind) $($leaf.Name)" }
            if ($leaf.Related) { & $missing $leaf.Related }
        }
    }

    $rows = foreach ($section in $policies) {
        $sequence = 0
        foreach ($policy in $section.Entries) {
            $sequence++
            $settings = $policy.Settings
            $get = { param([string]$Key) if ($settings.Contains($Key)) { @($settings[$Key]) } else { @() } }
            $one = { param([string]$Key, [string]$Default = '') $v = & $get $Key; if ($v.Count) { $v -join $Delimiter } else { $Default } }
            $resolve = {
                param([string]$Kind, [string[]]$Names)
                foreach ($name in $Names) { Resolve-NSPFortiGateReference -Index $index -Kind $Kind -Name $name -Vdom $policy.Vdom -Used $used }
            }
            $detail = {
                param($Leaves, [string]$NegateKey)
                $text = @($Leaves | ForEach-Object { & $label $_ } | Select-Object -Unique) -join $Delimiter
                if ($text -and (& $one $NegateKey) -eq 'enable') { $text = "NOT: $text" }
                $text
            }

            $interfaces = @(& $resolve Interface (@(& $get 'srcintf') + @(& $get 'dstintf')))
            $source = @(& $resolve Address (@(& $get 'srcaddr') + @(& $get 'srcaddr6')))
            $destination = @(& $resolve Address (@(& $get 'dstaddr') + @(& $get 'dstaddr6')))
            $services = @(& $resolve Service (& $get 'service'))
            $groups = @(& $resolve User (& $get 'groups'))
            $users = @(& $resolve User (& $get 'users'))

            $tunnels = @($interfaces | Where-Object Path -eq 'vpn ipsec phase1-interface')
            $vpn = @($tunnels | ForEach-Object { & $label $_ } | Select-Object -Unique)
            $vpnPeers = @(& $peers $tunnels | Select-Object -Unique)
            $groupMatch = foreach ($group in $groups) {
                if (-not $group.Entry) { continue }
                foreach ($match in @($group.Entry.Sections | Where-Object Path -eq 'match')) {
                    foreach ($rule in $match.Entries) {
                        $text = (@('server-name', 'group-name') | Where-Object { $rule.Settings.Contains($_) } | ForEach-Object { $rule.Settings[$_] -join ' ' }) -join ': '
                        if ($groups.Count -gt 1) { "$($group.Name) -> $text" } else { $text }
                    }
                }
            }
            $groupMembers = foreach ($group in $groups) {
                if ($group.Entry -and $group.Entry.Settings.Contains('member')) {
                    $members = $group.Entry.Settings['member'] -join ', '
                    if ($groups.Count -gt 1) { "$($group.Name) -> $members" } else { $members }
                }
            }

            $row = [ordered]@{}
            if ($showVdom) { $row.Vdom = $policy.Vdom }
            $row.Sequence = $sequence
            $row.PolicyId = $policy.Name
            $row.Name = & $one 'name'
            $row.Status = & $one 'status' 'enable'
            $row.Action = & $one 'action' 'deny'
            $row.SrcIntf = & $one 'srcintf'
            $row.DstIntf = & $one 'dstintf'
            $row.Vpn = $vpn -join $Delimiter
            $row.VpnPeers = $vpnPeers -join $Delimiter
            $row.Groups = & $one 'groups'
            $row.GroupMatch = @($groupMatch) -join $Delimiter
            $row.GroupMembers = @($groupMembers) -join $Delimiter
            $row.Users = & $one 'users'
            $row.SrcAddr = & $one 'srcaddr'
            $row.SrcAddrDetail = & $detail $source 'srcaddr-negate'
            $row.DstAddr = & $one 'dstaddr'
            $row.DstAddrDetail = & $detail $destination 'dstaddr-negate'
            $row.Service = & $one 'service'
            $row.ServiceDetail = & $detail $services 'service-negate'
            $row.Schedule = & $one 'schedule'
            $row.Nat = & $one 'nat' 'disable'
            $row.Comments = & $one 'comments'
            $row.Unresolved = @(& $missing ($interfaces + $source + $destination + $services + $groups + $users) | Select-Object -Unique) -join $Delimiter
            [pscustomobject]$row
        }
    }

    foreach ($phase2 in (Find-NSPFortiGateSection -Section $Tree -Pattern 'vpn ipsec phase2-interface')) {
        foreach ($entry in $phase2.Entries) {
            if (-not $entry.Settings.Contains('phase1name')) { continue }
            $phase1 = $entry.Settings['phase1name'][0]
            $isUsed = @($entry.Vdom, 'global', '') | Where-Object { $used.Contains((Get-NSPFortiGateObjectKey -Vdom $_ -Path 'vpn ipsec phase1-interface' -Name $phase1)) }
            if ($isUsed) { [void]$used.Add((Get-NSPFortiGateObjectKey -Vdom $entry.Vdom -Path $phase2.Path -Name $entry.Name)) }
        }
    }

    @{ Rows = @($rows); Used = $used; PolicyCount = @($policies | ForEach-Object { $_.Entries }).Count }
}
