function Get-NSPFortiGateVpnReportData {
    <#
    .SYNOPSIS
        Builds every sheet of the VPN report as plain data, for HTML and Excel rendering alike.
    .DESCRIPTION
        Returns Title, DeviceName, TunnelName, Facts (tunnel settings), NpsFacts (the NPS server:
        -NpsFacts entries plus the RADIUS clients in ias.xml), Sources, Checks (findings
        worth a reader's attention), PolicyCount, and Sheets. Each sheet has Title, Intro, Notes,
        Columns, Rows (hashtables keyed by column; '_class' marks a row), SpanColumns (merged in
        HTML), NoWrapColumns, Empty (text when there are no rows), and Placeholder (text when the
        sheet's source was not supplied; Rows is then empty).

        Sources: FortiGate captures (always), the NPS ias.xml (-NpsConfig: NPS and effective-access
        sheets), and AD-Manager's inventory JSON (-AdInventory: AD tree and certificate template
        sheets, SID names, user counts, and which users an earlier NPS policy shadows).

        With ias.xml, every address the FortiGate sends RADIUS from (-RadiusSourceIp, and the
        'set source-ip' of each RADIUS server the tunnel's user groups match on) is checked against
        its RADIUS clients: NPS silently drops requests from an address that isn't one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [string]$Tunnel,
        [string]$NpsConfig,
        [string]$AdInventory,
        [string[]]$RadiusSourceIp,
        [System.Collections.IDictionary]$NpsFacts,
        [string]$DeviceName,
        [string]$Title
    )

    $files = @(foreach ($item in $Path) { if (Test-Path -LiteralPath $item) { Get-Item -LiteralPath $item } else { Get-Item -Path $item } })
    $tree = Read-NSPFortiGateInput -Path $Path
    $index = Get-NSPFortiGateIndex -Tree $tree
    $used = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $checks = New-Object System.Collections.Generic.List[string]

    if (-not $DeviceName) {
        foreach ($file in $files) {
            $prompt = Select-String -LiteralPath $file.FullName -Pattern '^(\S+?)(?: \([^)]*\))? # ' | Select-Object -First 1
            if ($prompt) { $DeviceName = $prompt.Matches[0].Groups[1].Value; break }
        }
        # A configuration backup has no CLI prompt; its hostname is in 'config system global'.
        if (-not $DeviceName) {
            $global = @(Find-NSPFortiGateSection -Section $tree -Pattern 'system global' | Where-Object { $_.Settings.Contains('hostname') })
            if ($global.Count) { $DeviceName = @($global[0].Settings['hostname'])[0] }
        }
        if (-not $DeviceName) { $DeviceName = 'FortiGate' }
    }

    # Policies in capture order, limited to the tunnel.
    $policies = New-Object System.Collections.Generic.List[object]
    foreach ($section in (Find-NSPFortiGateSection -Section $tree -Pattern 'firewall policy')) {
        $sequence = 0
        foreach ($entry in $section.Entries) {
            $sequence++
            $interfaces = @($entry.Settings['srcintf']) + @($entry.Settings['dstintf'])
            if ($Tunnel -and $interfaces -notcontains $Tunnel) { continue }
            $policies.Add([pscustomobject]@{ Sequence = $sequence; Entry = $entry })
        }
    }
    if ($policies.Count -eq 0) {
        $scope = if ($Tunnel) { " using interface '$Tunnel'" } else { '' }
        throw "No firewall policies$scope were found in the input."
    }
    $tunnelName = if ($Tunnel) { $Tunnel } else { 'all tunnels' }
    if (-not $Title) { $Title = "$DeviceName VPN access: $tunnelName" }

    $setting = {
        param($Entry, [string]$Key, [string]$Default = '')
        if ($Entry.Settings.Contains($Key) -and @($Entry.Settings[$Key]).Count) { @($Entry.Settings[$Key]) -join "`n" } else { $Default }
    }
    $isDisabled = { param($Entry) (& $setting $Entry 'status' 'enable') -eq 'disable' }
    $policyLabel = {
        param($Policy)
        $text = "#$($Policy.Entry.Name) $(& $setting $Policy.Entry 'name')".Trim()
        if (& $isDisabled $Policy.Entry) { "$text (disabled)" } else { $text }
    }

    # Who references what: object name -> list of "#id" or tunnel role, in first-seen order.
    $usage = @{ Address = [ordered]@{}; Service = [ordered]@{}; User = [ordered]@{} }
    $addUse = {
        param([string]$Kind, [string[]]$Names, [string]$By)
        foreach ($name in $Names) {
            if (-not $name) { continue }
            if (-not $usage[$Kind].Contains($name)) { $usage[$Kind][$name] = New-Object System.Collections.Generic.List[string] }
            if (-not $usage[$Kind][$name].Contains($By)) { $usage[$Kind][$name].Add($By) }
        }
    }
    $policiesByGroup = @{}
    foreach ($policy in $policies) {
        $settings = $policy.Entry.Settings
        $by = "#$($policy.Entry.Name)"
        foreach ($key in 'srcaddr', 'srcaddr6', 'dstaddr', 'dstaddr6') { if ($settings.Contains($key)) { & $addUse Address $settings[$key] $by } }
        if ($settings.Contains('service')) { & $addUse Service $settings['service'] $by }
        foreach ($key in 'groups', 'users') { if ($settings.Contains($key)) { & $addUse User $settings[$key] $by } }
        foreach ($group in @($settings['groups'])) {
            if (-not $group) { continue }
            if (-not $policiesByGroup.ContainsKey($group)) { $policiesByGroup[$group] = New-Object System.Collections.Generic.List[object] }
            $policiesByGroup[$group].Add($policy)
        }
    }

    $phase1 = $null
    if ($Tunnel) {
        $leaf = Resolve-NSPFortiGateReference -Index $index -Kind Interface -Name $Tunnel -Vdom $policies[0].Entry.Vdom -Used $used
        if ($leaf.Path -eq 'vpn ipsec phase1-interface') { $phase1 = $leaf.Entry }
    }
    if ($phase1) {
        foreach ($pair in @(@('ipv4-name', 'Tunnel client pool'), @('ipv4-split-include', 'Tunnel split tunnel'), @('ipv4-split-exclude', 'Tunnel split exclude'))) {
            if ($phase1.Settings.Contains($pair[0])) { & $addUse Address $phase1.Settings[$pair[0]] $pair[1] }
        }
    }
    # A PSK/EAP tunnel (no 'authmethod signature', no peer) has no certificate peers or templates to
    # document: those sheets say so instead of reading as missing data.
    $certTunnel = -not $phase1 -or (& $setting $phase1 'authmethod' 'psk') -eq 'signature' -or (& $setting $phase1 'peergrp') -or (& $setting $phase1 'peer')
    $notCertText = "Not applicable: tunnel $Tunnel authenticates with a pre-shared key$(if ($phase1 -and (& $setting $phase1 'eap') -eq 'enable') { ' and EAP' }), not certificates."
    $usedBy = { param([string]$Kind, [string]$Name) $usage[$Kind][$Name] -join ', ' }
    $summary = {
        param($Leaf)
        if ($Leaf.Missing) { return '(not in the captures)' }
        if (-not $Leaf.Entry) { return '(built-in)' }
        Get-NSPFortiGateObjectSummary -Path $Leaf.Path -Settings $Leaf.Entry.Settings
    }
    $entriesOf = {
        param([string]$SectionPath)
        foreach ($key in $index.Keys) { if ($key -like "*`t$SectionPath") { $index[$key].Values } }
    }

    # Every FortiGate user group match rule: group -> RADIUS server -> expected VSA.
    $fgtMatches = @(foreach ($entry in (& $entriesOf 'user group')) {
        foreach ($match in @($entry.Sections | Where-Object Path -eq 'match')) {
            foreach ($rule in $match.Entries) {
                [pscustomobject]@{ Group = $entry.Name; Server = & $setting $rule 'server-name'; Vsa = & $setting $rule 'group-name' }
            }
        }
    })

    # ---- NPS and AD sources ------------------------------------------------------------------
    $npsPolicies = @()
    if ($NpsConfig) { $npsPolicies = @(Read-NSPFortiGateNpsPolicy -Path $NpsConfig) }
    $networkPolicies = @($npsPolicies | Where-Object Type -eq 'NetworkPolicy')
    $requestPolicies = @($npsPolicies | Where-Object Type -eq 'ConnectionRequest')
    $npsClients = @()
    if ($NpsConfig) { $npsClients = @(Read-NSPFortiGateNpsClient -Path $NpsConfig) }

    $ad = $null
    $adBySid = @{}
    if ($AdInventory) {
        $ad = Get-Content -LiteralPath $AdInventory -Raw | ConvertFrom-Json
        if ($ad.SchemaVersion -ne 1) { throw "Unsupported AD inventory SchemaVersion '$($ad.SchemaVersion)' in '$AdInventory' (expected 1)." }
        foreach ($group in @($ad.Groups)) { if ($group.Sid) { $adBySid[$group.Sid] = $group } }
    }
    $sidCache = @{}
    $sidName = {
        param([string]$Sid)
        if ($adBySid.ContainsKey($Sid)) { return $adBySid[$Sid].Name }
        if (-not $sidCache.ContainsKey($Sid)) {
            $sidCache[$Sid] = try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value -replace '^.*\\', '' } catch { $Sid }
        }
        $sidCache[$Sid]
    }
    $conditionText = {
        param($Policy)
        @(foreach ($condition in $Policy.Conditions) {
            if ($condition -match '^USERNTGROUPS\((.*)\)$') {
                'Member of: ' + (@([regex]::Matches($Matches[1], '"([^"]+)"') | ForEach-Object { & $sidName $_.Groups[1].Value }) -join ' or ')
            } elseif ($condition -match '^MATCH\("Client-IP-Address=([^"]+)"\)$') {
                "RADIUS client $($Matches[1])"
            } elseif ($condition -match '^TIMEOFDAY\("(\d 00:00-24:00; ){6}\d 00:00-24:00"\)$') {
                'Any time'
            } else { $condition }
        }) -join "`n"
    }
    $npsLabel = { param($Policy) "$($Policy.Sequence). $($Policy.Name)" }
    # What one VSA lands on: exact (case-sensitive) FortiGate matches, and case-only near misses.
    $vsaTarget = {
        param([string]$Vsa)
        [pscustomobject]@{
            Exact = @($fgtMatches | Where-Object { $_.Vsa -ceq $Vsa })
            CaseOnly = @($fgtMatches | Where-Object { $_.Vsa -ieq $Vsa -and $_.Vsa -cne $Vsa })
        }
    }

    # ---- Sheet 1: policies -------------------------------------------------------------------
    $policyRows = foreach ($policy in $policies) {
        $entry = $policy.Entry
        $source = & $setting $entry 'srcaddr'
        $destination = & $setting $entry 'dstaddr'
        if ((& $setting $entry 'srcaddr-negate') -eq 'enable') { $source = "NOT $source" }
        if ((& $setting $entry 'dstaddr-negate') -eq 'enable') { $destination = "NOT $destination" }
        @{
            '_class' = if (& $isDisabled $entry) { 'disabled' } else { '' }
            'Seq' = $policy.Sequence
            'ID' = $entry.Name
            'Name' = & $setting $entry 'name'
            'Status' = if (& $isDisabled $entry) { 'disabled' } else { 'enabled' }
            'Action' = & $setting $entry 'action' 'deny'
            'From' = & $setting $entry 'srcintf'
            'To' = & $setting $entry 'dstintf'
            'User groups' = & $setting $entry 'groups'
            'Source' = $source
            'Destination' = $destination
            'Services' = & $setting $entry 'service'
            'Comments' = (& $setting $entry 'comments').Trim()
        }
    }

    # ---- Sheet 2: user groups and their RADIUS match -----------------------------------------
    $sentBy = {
        param([string]$Vsa, [string]$Group)
        if (-not $npsPolicies.Count) { return '' }
        $senders = @($networkPolicies | Where-Object { $_.Enabled -and $_.Vsas -ccontains $Vsa })
        if ($senders.Count) { return (($senders | ForEach-Object { & $npsLabel $_ }) -join "`n") }
        $near = @($networkPolicies | Where-Object { $_.Enabled -and $_.Vsas -icontains $Vsa })
        if ($near.Count) {
            $actual = @($near[0].Vsas | Where-Object { $_ -ieq $Vsa })[0]
            $checks.Add("FortiGate user group '$Group' expects VSA '$Vsa', but NPS sends '$actual'. Matching is case-sensitive, so it never matches.")
            return "(none: NPS sends '$actual', case differs)"
        }
        $checks.Add("FortiGate user group '$Group' expects VSA '$Vsa', which no enabled NPS policy sends.")
        '(no NPS policy sends this)'
    }
    $groupColumns = @('User group', 'Used by', 'Match server', 'VSA expected (group-name)')
    if ($npsPolicies.Count) { $groupColumns += 'Sent by NPS policy' }
    $groupColumns += 'Members'
    $groupRows = foreach ($name in $usage.User.Keys) {
        $leaf = Resolve-NSPFortiGateReference -Index $index -Kind User -Name $name -Used $used
        $base = @{ 'User group' = $name; 'Used by' = & $usedBy User $name }
        $rules = @(if ($leaf.Entry) { $leaf.Entry.Sections | Where-Object Path -eq 'match' | ForEach-Object { $_.Entries } })
        if ($leaf.Missing) {
            $base + @{ 'Match server' = '(not in the captures)'; 'Members' = '' }
        } elseif ($rules.Count -eq 0) {
            $base + @{ 'Members' = & $setting $leaf.Entry 'member' }
        } else {
            foreach ($rule in $rules) {
                $vsa = & $setting $rule 'group-name'
                $base + @{ 'Match server' = & $setting $rule 'server-name'; 'VSA expected (group-name)' = $vsa; 'Sent by NPS policy' = & $sentBy $vsa $name; 'Members' = & $setting $leaf.Entry 'member' }
            }
        }
    }

    # ---- Sheets 3 and 4: services and addresses, expanded ------------------------------------
    $expand = {
        param([string]$Kind, [string]$Name, [string]$MemberColumn, [string]$DetailColumn)
        foreach ($leaf in @(Resolve-NSPFortiGateReference -Index $index -Kind $Kind -Name $Name -Used $used)) {
            $member = if (@($leaf.Via).Count -gt 0) { $leaf.Name } else { '(not grouped)' }
            if ($leaf.Excluded) { $member = "NOT $member" }
            @{
                'Group' = $Name
                'Used by' = & $usedBy $Kind $Name
                $MemberColumn = $member
                'Type' = if ($leaf.Entry -and $leaf.Entry.Settings.Contains('type')) { @($leaf.Entry.Settings['type'])[0] } else { '' }
                $DetailColumn = & $summary $leaf
                'Via' = if (@($leaf.Via).Count -gt 1) { @($leaf.Via)[1..(@($leaf.Via).Count - 1)] -join ' > ' } else { '' }
            }
        }
    }
    $serviceRows = foreach ($name in $usage.Service.Keys) { & $expand Service $name 'Service' 'Protocol / ports' }
    $addressRows = foreach ($name in $usage.Address.Keys) { & $expand Address $name 'Member' 'Resolves to' }

    # ---- Certificate templates (needed by sheets 5 and 8) ------------------------------------
    $templates = @(if ($ad) { $ad.Templates })
    $ouPattern = { param([string]$Ou) '(?i)(^|[,/]\s*)OU=' + [regex]::Escape($Ou) + '\s*($|[,/])' }
    $templatesForSubject = {
        param([string]$Subject)
        @($templates | Where-Object { $_.OuStamp -and $Subject -match (& $ouPattern $_.OuStamp) })
    }
    $shortName = { param([string]$Name) $Name -replace '^.*\\', '' }
    $isAdminPrincipal = { param([string]$Name) $Name -match '(?i)\\(Domain Admins|Enterprise Admins)$|^NT AUTHORITY\\|^BUILTIN\\' }

    # ---- Sheet 5: certificate peers accepted by the tunnel -----------------------------------
    $peerColumns = @('Peer group', 'Used by', 'Peer', 'CA', 'Subject match', 'MFA server')
    if ($ad) { $peerColumns += 'Issued by template' }
    $tunnelPeers = @()
    $peerRows = @()
    if ($phase1) {
        $peerRows = foreach ($peerGroup in @(@($phase1.Settings['peergrp']) | Where-Object { $_ })) {
            $groupLeaf = Resolve-NSPFortiGateReference -Index $index -Kind User -Name $peerGroup -Used $used
            $members = if ($groupLeaf.Entry) { @($groupLeaf.Entry.Settings['member']) } else { @() }
            if ($members.Count -eq 0) { @{ 'Peer group' = $peerGroup; 'Used by' = "Tunnel $Tunnel"; 'Peer' = '(not in the captures)' } }
            foreach ($member in $members) {
                $peer = Resolve-NSPFortiGateReference -Index $index -Kind User -Name $member -Used $used
                $row = @{ 'Peer group' = $peerGroup; 'Used by' = "Tunnel $Tunnel"; 'Peer' = $member }
                if ($peer.Entry) {
                    $subject = & $setting $peer.Entry 'subject'
                    $row['CA'] = & $setting $peer.Entry 'ca'
                    $row['Subject match'] = $subject
                    $row['MFA server'] = & $setting $peer.Entry 'mfa-server'
                    $tunnelPeers += [pscustomobject]@{ Name = $member; Group = $peerGroup; Subject = $subject }
                    if ($ad) {
                        $issuers = @(& $templatesForSubject $subject)
                        $row['Issued by template'] = if ($issuers.Count) { ($issuers | ForEach-Object Name) -join "`n" } elseif ($subject) { '(no template stamps this OU)' } else { '' }
                        if ($subject -and -not $issuers.Count) { $checks.Add("Tunnel peer '$member' matches subject '$subject', but no collected certificate template stamps that OU.") }
                    }
                } else { $row['CA'] = '(not in the captures)' }
                $row
            }
        }
    }

    # ---- Sheet 6: NPS configuration ----------------------------------------------------------
    $npsRows = foreach ($policy in $networkPolicies) {
        $base = @{
            '_class' = if ($policy.Enabled) { '' } else { 'disabled' }
            'Order' = $policy.Sequence
            'NPS policy' = $policy.Name
            'Status' = if ($policy.Enabled) { 'enabled' } else { 'disabled' }
            'Conditions' = & $conditionText $policy
        }
        if (-not $policy.Vsas.Count) { $base + @{ 'VSA returned' = '(none)' } }
        foreach ($vsa in $policy.Vsas) {
            $target = & $vsaTarget $vsa
            $landsIn = New-Object System.Collections.Generic.List[string]
            $unlocks = New-Object System.Collections.Generic.List[string]
            foreach ($match in $target.Exact) {
                if ($policiesByGroup.ContainsKey($match.Group)) {
                    $landsIn.Add($match.Group)
                    foreach ($firewall in $policiesByGroup[$match.Group]) { $unlocks.Add((& $policyLabel $firewall)) }
                } else { $landsIn.Add("$($match.Group) (not used by this tunnel)") }
            }
            foreach ($match in $target.CaseOnly) { $landsIn.Add("(no match: $($match.Group) expects '$($match.Vsa)')") }
            if (-not $target.Exact.Count -and -not $target.CaseOnly.Count) {
                $landsIn.Add('(no FortiGate user group)')
                if ($policy.Enabled) { $checks.Add("NPS policy '$($policy.Name)' sends VSA '$vsa', which no FortiGate user group matches.") }
            }
            $base + @{ 'VSA returned' = $vsa; 'FortiGate user group' = $landsIn -join "`n"; 'Unlocks (this tunnel)' = ($unlocks | Select-Object -Unique) -join "`n" }
        }
    }
    $npsNotes = @(
        'NPS evaluates network policies in Order and stops at the first match: a user receives the VSAs of the first policy whose conditions they meet, never a combination.',
        'The FortiGate places a user in every local user group whose match rule names one of the returned VSAs. That match is case-sensitive.'
    )
    if ($requestPolicies.Count) {
        $npsNotes += 'Connection request policies: ' + (($requestPolicies | ForEach-Object { "$(& $npsLabel $_) ($((& $conditionText $_) -replace "`n", ', '))" }) -join '; ') + '.'
    }

    # ---- Sheet 7: AD group membership --------------------------------------------------------
    # VPN templates: those TameMyCerts stamps, or that auto-enroll a group an NPS policy authorizes.
    # The inventory also carries built-ins (Workstation, RASAndIASServer, ...) that are not part of the story.
    $npsGroupNames = @($networkPolicies | ForEach-Object { $_.GroupSids } | ForEach-Object { & $sidName $_ })
    $vpnTemplates = @($templates | Where-Object { $certTunnel } | Where-Object {
        $_.OuStamp -or @($_.AutoEnroll | Where-Object { -not (& $isAdminPrincipal $_.Name) -and $npsGroupNames -contains (& $shortName $_.Name) }).Count
    })
    $adRows = @()
    $omittedGroups = 0
    if ($ad) {
        $roles = @{}
        $addRole = { param([string]$Group, [string]$Role, [int]$Rank) if (-not $roles.ContainsKey($Group)) { $roles[$Group] = @{ Rank = $Rank; Text = New-Object System.Collections.Generic.List[string] } }; $roles[$Group].Text.Add($Role); if ($Rank -lt $roles[$Group].Rank) { $roles[$Group].Rank = $Rank } }
        foreach ($policy in $networkPolicies) { foreach ($sid in $policy.GroupSids) { & $addRole (& $sidName $sid) "NPS policy $(& $npsLabel $policy)" $policy.Sequence } }
        foreach ($template in $vpnTemplates) {
            foreach ($principal in @($template.AutoEnroll)) { if (-not (& $isAdminPrincipal $principal.Name)) { & $addRole (& $shortName $principal.Name) "Auto-enrolls $($template.Name)" 100000 } }
        }
        # Relevant groups: any with a role or matching the export's name patterns, plus their direct
        # parents and nested member groups. Drops admin and built-in groups reached only through ACLs.
        $patterns = @($ad.Sources.GroupPattern | Where-Object { $_ })
        if (-not $patterns.Count) { $patterns = @('IKEv2*', 'VPNFW*', 'FGT*') }
        $relevant = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($group in @($ad.Groups)) {
            if ($roles.ContainsKey($group.Name) -or @($patterns | Where-Object { $group.Name -like $_ }).Count) { [void]$relevant.Add($group.Name) }
        }
        foreach ($group in @($ad.Groups | Where-Object { $relevant.Contains($_.Name) })) {
            foreach ($parent in @($group.MemberOf)) { if (-not (& $isAdminPrincipal "\$($parent.Name)")) { [void]$relevant.Add($parent.Name) } }
            foreach ($member in @($group.Members | Where-Object Class -eq 'group')) { [void]$relevant.Add($member.Name) }
        }
        $shown = @($ad.Groups | Where-Object { $relevant.Contains($_.Name) })
        $omittedGroups = @($ad.Groups).Count - $shown.Count
        $ordered = @($shown | Sort-Object @{ Expression = { if ($roles.ContainsKey($_.Name)) { $roles[$_.Name].Rank } else { 200000 } } }, Name)
        $adRows = foreach ($group in $ordered) {
            $users = @($group.RecursiveUsers)
            $disabled = @($users | Where-Object { $_.Enabled -eq $false }).Count
            $base = @{
                'Group' = $group.Name
                'Role' = if ($roles.ContainsKey($group.Name)) { $roles[$group.Name].Text -join "`n" } else { '' }
                'Member of' = (@($group.MemberOf) | ForEach-Object Name) -join "`n"
                'Users (all levels)' = if ($disabled) { "$($users.Count) ($disabled disabled)" } else { "$($users.Count)" }
            }
            $members = @($group.Members | Sort-Object @{ Expression = { $_.Class -ne 'group' } }, Name)
            if (-not $members.Count) { $base + @{ 'Member' = '(no members)' } }
            foreach ($member in $members) {
                $base + @{ 'Member' = $member.Name; 'Type' = $member.Class; 'Account' = if ($member.Enabled -eq $false) { 'disabled' } else { '' } }
            }
        }
    }

    # ---- Sheet 8: certificate templates ------------------------------------------------------
    $templateRows = foreach ($template in $vpnTemplates) {
        $auto = @($template.AutoEnroll | Where-Object { -not (& $isAdminPrincipal $_.Name) } | ForEach-Object { & $shortName $_.Name })
        $autoSids = @($template.AutoEnroll | ForEach-Object Sid)
        $manual = @($template.Enroll | Where-Object { $autoSids -notcontains $_.Sid -and -not (& $isAdminPrincipal $_.Name) } | ForEach-Object { & $shortName $_.Name })
        $peersForStamp = if ($template.OuStamp) { @($tunnelPeers | Where-Object { $_.Subject -and $_.Subject -match (& $ouPattern $template.OuStamp) }) } else { @() }
        if ($auto.Count -and -not $template.OuStamp) { $checks.Add("Template '$($template.Name)' auto-enrolls $($auto -join ', ') but has no TameMyCerts OU stamp.") }
        @{
            'Template' = $template.Name
            'Display name' = $template.DisplayName
            'Auto-enroll groups' = $auto -join "`n"
            'Enroll only' = $manual -join "`n"
            'Validity' = if ($template.ValidityDays) { "$($template.ValidityDays) days, renew $($template.RenewalDays) days before" } else { '' }
            'Subject' = if ($template.EnrolleeSuppliesSubject) { 'supplied in request' } else { 'built from AD' }
            'OU stamp (TameMyCerts)' = if ($template.OuStamp) { "OU=$($template.OuStamp)" } else { '(none)' }
            'FortiGate peer (this tunnel)' = ($peersForStamp | ForEach-Object { "$($_.Name) ($($_.Group))" }) -join "`n"
            'Published on' = @($template.PublishedOn) -join "`n"
        }
    }
    $templateNotes = @(
        'Included are the group memberships tied to auto-enrollment (and enrollment-only grants, typically the MANUAL templates).',
        "The 'OU=' stamp is not part of the template. The TameMyCerts policy module on the CA forces it into every certificate the template issues; the FortiGate peer then matches it with 'set subject'."
    )
    if ($templates.Count -gt $vpnTemplates.Count) { $templateNotes += "Shown: templates with a TameMyCerts OU stamp or that auto-enroll an NPS-authorized group. $($templates.Count - $vpnTemplates.Count) other client-authentication templates in the AD inventory are left out." }
    # TameMyCerts applies a policy file to the template whose name matches the file's; a policy with no
    # such template in AD (deleted, renamed, or not yet replicated) stamps nothing.
    $templateNames = @($templates | ForEach-Object Name)
    $orphanPolicies = @(if ($ad -and $ad.TameMyCerts) { @($ad.TameMyCerts.Policies) | Where-Object { $_.Template -and $templateNames -notcontains $_.Template } })
    if ($certTunnel -and $orphanPolicies.Count) {
        $orphanList = ($orphanPolicies | ForEach-Object { "$($_.Template) (OU=$($_.OuValue))" }) -join ', '
        $templateNotes += "TameMyCerts policies with no certificate template of that name in AD: $orphanList. They stamp nothing until a template with the policy's exact name exists."
        $checks.Add("$($orphanPolicies.Count) TameMyCerts policy file(s) match no certificate template in AD: $orphanList. The template may be deleted, renamed, or not yet replicated.")
    }
    if ($ad -and $ad.TameMyCerts -and $ad.TameMyCerts.PolicyDirectory) { $templateNotes += "TameMyCerts policy folder: $($ad.TameMyCerts.PolicyDirectory)." }
    elseif ($ad) { $templateNotes += 'The AD inventory did not include the TameMyCerts policy folder, so OU stamps are unknown. Run the export on the CA, or give it the folder.' }
    if (-not $certTunnel) { $templateRows = @(); $templateNotes = @() }

    # ---- Sheet 9: effective access by AD group -----------------------------------------------
    $usersOfSid = { param([string]$Sid) if ($adBySid.ContainsKey($Sid)) { @($adBySid[$Sid].RecursiveUsers) } else { $null } }
    # Users meeting every USERNTGROUPS condition (each satisfied by any one of its groups); $null when unknown.
    $usersOfPolicy = {
        param($Policy)
        $result = $null
        foreach ($condition in $Policy.Conditions) {
            if ($condition -notmatch '^USERNTGROUPS\((.*)\)$') { continue }
            $set = @{}
            foreach ($sid in ([regex]::Matches($Matches[1], '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })) {
                $members = & $usersOfSid $sid
                if ($null -eq $members) { return $null }
                foreach ($user in $members) { $set[$user.DistinguishedName] = $user }
            }
            if ($null -eq $result) { $result = $set } else { foreach ($key in @($result.Keys)) { if (-not $set.ContainsKey($key)) { $result.Remove($key) } } }
        }
        $result
    }
    # A rule's addresses or services, each name followed by what it resolves to (groups expanded,
    # long groups cut short; the Address groups and Service groups sheets have them in full).
    $describe = {
        param([string]$Kind, [string[]]$Names, [bool]$Negate)
        $limit = 6
        $lines = foreach ($name in @($Names | Where-Object { $_ })) {
            $details = @(@(foreach ($leaf in @(Resolve-NSPFortiGateReference -Index $index -Kind $Kind -Name $name -Used $used)) {
                $text = & $summary $leaf
                # An FQDN address summarizes to its own name; say it once.
                if (@($leaf.Via).Count -gt 0 -and $text -ne $leaf.Name) { $text = "$($leaf.Name) $text" }
                if ($leaf.Excluded) { "NOT $text" } else { $text }
            }) | Select-Object -Unique)
            if ($details.Count -gt $limit) { $details = @($details[0..($limit - 1)]) + "(+$($details.Count - $limit) more)" }
            # Members are separated by '; ' since one member's summary can hold commas (TCP/53, UDP/53).
            if ($details.Count -eq 1 -and $details[0] -eq $name) { $name } else { "${name}: $($details -join '; ')" }
        }
        $text = @($lines) -join "`n"
        if ($Negate) { "NOT $text" } else { $text }
    }
    $accessRows = @()
    $earlier = New-Object System.Collections.Generic.List[object]
    foreach ($policy in @($networkPolicies | Where-Object Enabled)) {
        $members = if ($ad) { & $usersOfPolicy $policy } else { $null }
        $shadowText = ''
        if ($null -ne $members) {
            $byEarlier = [ordered]@{}
            foreach ($key in $members.Keys) {
                foreach ($prior in $earlier) {
                    if ($null -ne $prior.Members -and $prior.Members.ContainsKey($key)) {
                        $label = & $npsLabel $prior.Policy
                        if (-not $byEarlier.Contains($label)) { $byEarlier[$label] = @{ Prior = $prior.Policy; Names = New-Object System.Collections.Generic.List[string] } }
                        $byEarlier[$label].Names.Add(($members[$key].Name))
                        break
                    }
                }
            }
            $shadowCount = 0
            $shadowText = @(foreach ($label in $byEarlier.Keys) {
                $prior = $byEarlier[$label].Prior
                $names = @($byEarlier[$label].Names | Sort-Object)
                $shadowCount += $names.Count
                $nameList = ($names | Select-Object -First 5) -join ', '
                if ($names.Count -gt 5) { $nameList += ", and $($names.Count - 5) more" }
                # Often by design (a combined policy placed first sends a superset); what matters is what is lost.
                $lost = @($policy.Vsas | Where-Object { $prior.Vsas -cnotcontains $_ })
                # Only a group some ENABLED rule on this tunnel uses is real access lost.
                $lostGroups = @($lost | ForEach-Object { (& $vsaTarget $_).Exact } | ForEach-Object Group | Where-Object {
                    $policiesByGroup.ContainsKey($_) -and @($policiesByGroup[$_] | Where-Object { -not (& $isDisabled $_.Entry) }).Count
                } | Select-Object -Unique)
                $impact = if (-not $lost.Count) { 'no VSAs lost' } elseif ($lostGroups.Count) { "loses $($lost -join ', '): no $($lostGroups -join ', ')" } else { "loses $($lost -join ', '), which unlock no enabled rule on this tunnel" }
                if ($lostGroups.Count) { $checks.Add("NPS policy '$($policy.Name)': $($names.Count) user(s) ($nameList) match policy $label first and so are not placed in $($lostGroups -join ', '), which enabled rules on this tunnel use.") }
                "$($names.Count) get policy $label instead ($impact): $nameList"
            }) -join "`n"
            if ($members.Count -and $shadowCount -eq $members.Count) { $checks.Add("NPS policy '$($policy.Name)' never applies: all $($members.Count) of its users match an earlier policy first.") }
        }
        $earlier.Add([pscustomobject]@{ Policy = $policy; Members = $members })
        # A policy returning no VSAs places nobody in a FortiGate group; it still shadows later ones (recorded above).
        if (-not $policy.Vsas.Count) { continue }
        $groupsText = (@($policy.GroupSids | ForEach-Object { & $sidName $_ }) -join "`n")
        $base = @{
            'Order' = $policy.Sequence
            'NPS policy' = $policy.Name
            'AD group' = $groupsText
            'Users' = if ($null -ne $members) { "$($members.Count)" } elseif ($ad) { '(group not in AD inventory)' } else { '' }
            'Also match an earlier policy' = $shadowText
        }
        foreach ($vsa in $policy.Vsas) {
            $target = & $vsaTarget $vsa
            $fgt = @($target.Exact | ForEach-Object Group | Select-Object -Unique)
            $vsaBase = $base + @{
                'VSA' = $vsa
                'FortiGate user group' = if ($fgt.Count) { $fgt -join "`n" } elseif ($target.CaseOnly.Count) { '(case differs, no match)' } else { '(none)' }
            }
            # One row per firewall rule the VSA unlocks, in evaluation order, with the rule written out.
            $reached = @(foreach ($group in $fgt) { if ($policiesByGroup.ContainsKey($group)) { $policiesByGroup[$group] } } )
            $reached = @($reached | Sort-Object Sequence -Unique)
            if (-not $reached.Count) { $accessRows += $vsaBase + @{ 'Firewall rule' = '(none on this tunnel)' } }
            foreach ($firewall in $reached) {
                $entry = $firewall.Entry
                $accessRows += $vsaBase + @{
                    '_class' = if (& $isDisabled $entry) { 'disabled' } else { '' }
                    'Firewall rule' = & $policyLabel $firewall
                    'Action' = & $setting $entry 'action' 'deny'
                    'To' = & $setting $entry 'dstintf'
                    'Source' = & $describe Address @($entry.Settings['srcaddr']) ((& $setting $entry 'srcaddr-negate') -eq 'enable')
                    'Destination' = & $describe Address @($entry.Settings['dstaddr']) ((& $setting $entry 'dstaddr-negate') -eq 'enable')
                    'Services' = & $describe Service @($entry.Settings['service']) $false
                }
            }
        }
    }

    # ---- Assemble ----------------------------------------------------------------------------
    $npsMissing = 'Not generated: pass -NpsConfig with a copy of the NPS server''s C:\Windows\System32\ias\ias.xml.'
    $adMissing = 'Not generated: pass -AdInventory with the JSON from AD-Manager menu 6 (Export VPN documentation inventory).'
    $sheets = @(
        @{ Title = 'Firewall policies'; Intro = "These are the firewall rules currently in place that are tied to VPN tunnel $tunnelName, in evaluation order (Seq). Object names are detailed on the following sheets."
           Notes = @(); Columns = @('Seq', 'ID', 'Name', 'Status', 'Action', 'From', 'To', 'User groups', 'Source', 'Destination', 'Services', 'Comments'); Rows = @($policyRows)
           NoWrapColumns = @('Seq', 'ID', 'Status', 'Action', 'From', 'To') }
        @{ Title = 'User groups'; Intro = 'These are the FortiGate user groups that are tied to the above firewall rules.'
           Notes = @('Users will likely be a member of more than one of these.', 'The match criteria is the Vendor-Specific Attribute (VSA) returned by the Network Policy Server (RADIUS).', 'VSAs are based on the AD group names by convention ONLY. They do NOT necessarily need to match.')
           Columns = $groupColumns; Rows = @($groupRows); SpanColumns = @('User group', 'Used by') }
        @{ Title = 'Service groups'; Intro = 'These are the service groups, and their associated services, used by the firewall policies.'
           Notes = @(); Columns = @('Group', 'Used by', 'Service', 'Protocol / ports', 'Via'); Rows = @($serviceRows); SpanColumns = @('Group', 'Used by') }
        @{ Title = 'Address groups'; Intro = 'These are the address groups, and their associated destinations, used by the firewall policies and the tunnel.'
           Notes = @(); Columns = @('Group', 'Used by', 'Member', 'Type', 'Resolves to', 'Via'); Rows = @($addressRows); SpanColumns = @('Group', 'Used by') }
        @{ Title = 'Peer groups'; Intro = 'These are the peer group(s) associated with the VPN, along with their members.'
           Notes = @("These matches are tied to the 'OU=' stamp described on the Certificate templates sheet.")
           Columns = $peerColumns; Rows = @($peerRows); SpanColumns = @('Peer group', 'Used by'); Empty = $(if ($certTunnel) { 'The tunnel names no peer group, or its capture was not loaded.' } else { $notCertText }) }
        @{ Title = 'NPS configuration'; Intro = 'This is the current NPS configuration, and the Vendor-Specific Attributes that get returned.'
           Notes = $npsNotes; Columns = @('Order', 'NPS policy', 'Status', 'Conditions', 'VSA returned', 'FortiGate user group', 'Unlocks (this tunnel)'); Rows = @($npsRows)
           SpanColumns = @('Order', 'NPS policy', 'Status', 'Conditions'); NoWrapColumns = @('Order', 'Status'); Placeholder = $(if (-not $npsPolicies.Count) { $npsMissing }) }
        @{ Title = 'AD group membership'; Intro = "This is the current AD group membership 'tree': each group's role, the groups it is nested in, and its direct members. Nested groups appear as members and again as their own entry."
           Notes = @(if ($omittedGroups) { "Shown: groups an NPS policy or VPN template uses, groups matching the export's name patterns, and their direct parents and nested groups. $omittedGroups other groups in the AD inventory (built-in and admin groups reached through template permissions) are left out." })
           Columns = @('Group', 'Role', 'Member of', 'Users (all levels)', 'Member', 'Type', 'Account'); Rows = @($adRows)
           SpanColumns = @('Group', 'Role', 'Member of', 'Users (all levels)'); Placeholder = $(if (-not $ad) { $adMissing }) }
        @{ Title = 'Certificate templates'; Intro = 'These are the current certificate templates.'
           Notes = $templateNotes; Columns = @('Template', 'Display name', 'Auto-enroll groups', 'Enroll only', 'Validity', 'Subject', 'OU stamp (TameMyCerts)', 'FortiGate peer (this tunnel)', 'Published on'); Rows = @($templateRows)
           Empty = $(if ($certTunnel) { 'The AD inventory lists no client-authentication templates.' } else { $notCertText }); Placeholder = $(if (-not $ad -and $certTunnel) { $adMissing }) }
        @{ Title = 'Effective access by AD group'; Intro = 'This is the whole path for each NPS-authorized AD group, read left to right: the first matching NPS policy, the VSAs it returns, the FortiGate user groups those land in, and each firewall rule those groups unlock, written out with its action, interface, source, destination, and services.'
           Notes = @('Firewall rules are in evaluation order within each VSA; disabled rules are greyed. Address and service groups are expanded in place (long groups are cut short; the Address groups and Service groups sheets list them in full).', "'Also match an earlier policy' lists users of this policy's groups who meet an earlier policy first; NPS gives them that policy's VSAs instead. That is often by design (a combined policy placed first sends a superset), so each line says which VSAs, if any, those users lose. Non-group conditions (RADIUS client, time of day) are not compared.", 'NPS policies that return no VSAs (such as the built-in defaults) place nobody in a FortiGate group and are left out; they are listed on the NPS configuration sheet.')
           Columns = @('Order', 'NPS policy', 'AD group', 'Users', 'Also match an earlier policy', 'VSA', 'FortiGate user group', 'Firewall rule', 'Action', 'To', 'Source', 'Destination', 'Services'); Rows = @($accessRows)
           SpanColumns = @('Order', 'NPS policy', 'AD group', 'Users', 'Also match an earlier policy', 'VSA', 'FortiGate user group'); NoWrapColumns = @('Order', 'Users', 'Action', 'To')
           ColumnWidth = @{ 'NPS policy' = '8%'; 'AD group' = '8%'; 'Also match an earlier policy' = '13%'; 'Firewall rule' = '9%'; 'Destination' = '16%'; 'Services' = '11%' }; Placeholder = $(if (-not $npsPolicies.Count) { $npsMissing }) }
    )

    $facts = [ordered]@{}
    if ($phase1) {
        $pool = & $setting $phase1 'ipv4-name'
        if ($pool) {
            $poolLeaf = Resolve-NSPFortiGateReference -Index $index -Kind Address -Name $pool -Used $used
            if ($poolLeaf.Entry) { $pool = "$pool ($(& $summary $poolLeaf))" }
        }
        $facts['Tunnel'] = $Tunnel
        $facts['Type'] = "IKEv$(& $setting $phase1 'ike-version' '1') $(if ((& $setting $phase1 'type' 'static') -eq 'dynamic') { 'dial-up' } else { & $setting $phase1 'type' })"
        $facts['Interface'] = "$(& $setting $phase1 'interface') $(& $setting $phase1 'local-gw')".Trim()
        $facts['Authentication'] = (@((& $setting $phase1 'authmethod' 'psk'), $(if ((& $setting $phase1 'eap') -eq 'enable') { 'EAP' })) | Where-Object { $_ }) -join ' + '
        $facts['Certificate'] = & $setting $phase1 'certificate'
        $facts['Peer group'] = & $setting $phase1 'peergrp'
        $facts['Client pool'] = $pool
        $facts['Split tunnel'] = & $setting $phase1 'ipv4-split-include'
        $facts['DNS servers'] = (@((& $setting $phase1 'ipv4-dns-server1'), (& $setting $phase1 'ipv4-dns-server2')) | Where-Object { $_ }) -join ', '
        $proposal = (& $setting $phase1 'proposal') -replace "`n", ', '
        $dhGroup = & $setting $phase1 'dhgrp'
        $facts['Proposal / DH'] = (@($proposal, $(if ($dhGroup) { "group $dhGroup" })) | Where-Object { $_ }) -join ' / '
        # A PSK/EAP tunnel has no certificate or peer group; leave unset settings off the cover.
        foreach ($key in @($facts.Keys)) { if (-not $facts[$key]) { $facts.Remove($key) } }
    }
    # ---- NPS server: RADIUS clients and the addresses the FortiGate sends from ------------------
    $npsServer = [ordered]@{}
    if ($NpsFacts) { foreach ($key in $NpsFacts.Keys) { if ("$($NpsFacts[$key])") { $npsServer[[string]$key] = [string]$NpsFacts[$key] } } }
    if ($npsClients.Count) {
        $npsServer['RADIUS clients'] = (@($npsClients | ForEach-Object { "$($_.Name) ($($_.Address)$(if (-not $_.Enabled) { ', disabled' }))" }) -join '; ')
        $senders = [ordered]@{}
        foreach ($ip in @($RadiusSourceIp | Where-Object { $_ })) { $senders[$ip.Trim()] = 'given as the RADIUS source address' }
        $matchServers = @($fgtMatches | Where-Object { $usage.User.Contains($_.Group) -and $_.Server } | ForEach-Object Server | Select-Object -Unique)
        foreach ($server in (& $entriesOf 'user radius')) {
            if ($matchServers -notcontains $server.Name) { continue }
            $sourceIp = & $setting $server 'source-ip'
            if ($sourceIp -and -not $senders.Contains($sourceIp)) { $senders[$sourceIp] = "source-ip of RADIUS server '$($server.Name)'" }
        }
        foreach ($ip in $senders.Keys) {
            $hits = @($npsClients | Where-Object { Test-NSPFortiGateAddressMatch -Ip $ip -Address $_.Address })
            if (-not $hits.Count) {
                $checks.Add("The FortiGate sends RADIUS from $ip ($($senders[$ip])), which is not a RADIUS client in ias.xml. NPS drops its requests without a reply.")
            } elseif (-not @($hits | Where-Object Enabled).Count) {
                $checks.Add("The FortiGate sends RADIUS from $ip ($($senders[$ip])), but its RADIUS client '$($hits[0].Name)' is disabled in ias.xml.")
            }
        }
    }

    $sources = @("FortiGate captures: $(($files | ForEach-Object Name) -join ', ')")
    if ($NpsConfig) { $sources += "NPS configuration: $(Split-Path -Leaf $NpsConfig) ($($networkPolicies.Count) network policies)" }
    if ($ad) { $sources += "AD inventory: $(Split-Path -Leaf $AdInventory) ($($ad.Domain), collected on $($ad.ComputerName) $(([datetime]$ad.Generated).ToString('yyyy-MM-dd HH:mm')))" }

    [pscustomobject]@{
        Title = $Title
        DeviceName = $DeviceName
        TunnelName = $tunnelName
        Facts = $facts
        NpsFacts = $npsServer
        Sources = $sources
        Checks = @($checks | Select-Object -Unique)
        PolicyCount = $policies.Count
        Sheets = $sheets
    }
}
