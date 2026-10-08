$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'NSP.FortiGate.psd1') -Force

function Assert-Equal($Actual, $Expected, $Message) {
    if ($Actual -ne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
}

$fixture = Join-Path $PSScriptRoot 'Fixtures\FortiGate.capture.sample.txt'

# Tree: prompts skipped, grep markers stripped, nested blocks kept.
$tree = @(ConvertFrom-NSPFortiGateConfig -Path $fixture)
Assert-Equal $tree.Count 11 'Section count'
Assert-Equal $tree[0].Path 'firewall policy' 'First section path'
Assert-Equal $tree[0].Entries[0].Settings['srcintf'][0] 'Tunnel-VPN' 'Marker stripped from value'
Assert-Equal $tree[0].Entries[0].Settings['comments'][0] 'Staff "server" access' 'Escaped quotes'
$groupEntry = ($tree | Where-Object Path -eq 'user group').Entries[0]
Assert-Equal $groupEntry.Sections[0].Entries[0].Settings['group-name'][0] 'vpn-staff' 'Nested match block'
Assert-Equal (($tree | Where-Object Path -eq 'firewall service custom').Entries[2].Settings['icmpcode']).Count 0 'Unset value is empty'

# Policy rows keep capture order and fill omitted defaults.
$policies = @(ConvertFrom-NSPFortiGatePolicy -Path $fixture)
Assert-Equal $policies.Count 2 'Policy count'
Assert-Equal $policies[0].PolicyId '20' 'Capture order, not ID order'
Assert-Equal $policies[1].Sequence 2 'Sequence'
Assert-Equal $policies[1].Status 'disable' 'Explicit status'
Assert-Equal $policies[1].Action 'deny' 'Default action'
Assert-Equal $policies[0].Nat 'disable' 'Default NAT'
Assert-Equal $policies[1].Groups 'VPN_Staff; Missing_Group' 'Joined multi-value'
Assert-Equal $policies[1].'dstaddr-negate' 'enable' 'Unmapped setting kept'
Assert-Equal $policies[0].'dstaddr-negate' '' 'Unmapped setting blank on other rows'
Assert-Equal @(ConvertFrom-NSPFortiGatePolicy -Path $fixture -NoDefaults)[1].Action '' 'NoDefaults'
Assert-Equal @(ConvertFrom-NSPFortiGatePolicy -Path $fixture -Delimiter '|')[1].Groups 'VPN_Staff|Missing_Group' 'Custom delimiter'
$piped = @(Get-Content -LiteralPath $fixture -Raw | ConvertFrom-NSPFortiGatePolicy)
Assert-Equal $piped.Count 2 'Pipeline text input'

# Sections: schema columns, computed summaries, nested match, redaction.
$addresses = @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'firewall address')
Assert-Equal $addresses.Count 7 'Address count'
Assert-Equal $addresses[5].Summary 'mac (4 addresses)' 'MAC list summary'
Assert-Equal $addresses[6].Summary 'dynamic ems-tag' 'Dynamic summary'
Assert-Equal $addresses[6].SubType 'ems-tag' 'SubType column'
Assert-Equal $addresses[0].Summary '192.0.2.10-192.0.2.50' 'Range summary'
Assert-Equal $addresses[1].Summary '198.51.100.10' 'Host summary drops /32'
Assert-Equal $addresses[2].Summary '198.51.100.0/24' 'Subnet summary'
Assert-Equal $addresses[2].Type 'ipmask' 'Default address type'
$services = @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'firewall service custom')
Assert-Equal $services[0].Summary 'TCP/53, UDP/53' 'Service summary'
Assert-Equal $services[2].Summary 'ICMP type 8' 'ICMP summary'
$groups = @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'user group')
Assert-Equal $groups[0].Match 'RADIUS-1: vpn-staff' 'Match column'
$radius = @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'user radius')
Assert-Equal $radius[0].secret '<redacted>' 'Secret redacted'
Assert-Equal @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'user radius' -IncludeSecrets)[0].secret 'ENC; AAAAexampleonlyAAAA' 'IncludeSecrets'
$phase1 = @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'vpn ipsec phase1-interface')
Assert-Equal $phase1[0].psksecret '<redacted>' 'PSK redacted'
Assert-Equal $phase1[0].Summary 'IKEv2 dial-up on wan1, pool VPN_Pool, peers Staff_Peers' 'Tunnel summary'

# Access report: references resolved through nested groups, tunnel, and user group.
$access = @(Get-NSPFortiGatePolicyAccess -Path $fixture)
Assert-Equal $access.Count 2 'Access row count'
Assert-Equal $access[0].Vpn 'Tunnel-VPN (IKEv2 dial-up on wan1, pool VPN_Pool, peers Staff_Peers)' 'Access VPN'
Assert-Equal $access[0].VpnPeers 'Peer_Staff (CA CA_Example, subject OU=vpn-staff, MFA RADIUS-1)' 'Access VPN peers'
Assert-Equal $access[0].GroupMatch 'RADIUS-1: vpn-staff' 'Access group match'
Assert-Equal $access[0].GroupMembers 'RADIUS-1' 'Access group members'
Assert-Equal $access[0].SrcAddrDetail 'VPN_Pool (192.0.2.10-192.0.2.50)' 'Access source'
Assert-Equal $access[0].DstAddrDetail 'Server_Net (198.51.100.0/24); NOT Server_A (198.51.100.10); Portal (portal.example.com)' 'Access nested destination'
Assert-Equal $access[0].ServiceDetail 'RDP (TCP/3389); PING (ICMP type 8); DNS (TCP/53, UDP/53)' 'Access nested services'
Assert-Equal $access[0].Unresolved '' 'Nothing unresolved'
Assert-Equal $access[1].DstAddrDetail 'NOT: all' 'Negated destination'
Assert-Equal $access[1].Unresolved 'User Missing_Group' 'Unresolved group'
Assert-Equal $access[1].GroupMatch 'VPN_Staff -> RADIUS-1: vpn-staff' 'Group prefix with several groups'

# Filtering to what the policies use.
$usedAddresses = @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'firewall address' -UsedByPolicy)
Assert-Equal (($usedAddresses | ForEach-Object Name) -join ',') 'VPN_Pool,Server_A,Server_Net,Portal' 'Used addresses'
Assert-Equal @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'firewall service custom' -UsedByPolicy).Count 3 'Used services'
Assert-Equal @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'user group' -UsedByPolicy).Count 1 'Used user groups'
Assert-Equal @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'user radius' -UsedByPolicy).Count 1 'Used RADIUS via match'
Assert-Equal (@(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'user peer' -UsedByPolicy) | ForEach-Object Name) 'Peer_Staff' 'Used peers via tunnel'
$usedPhase2 = @(ConvertFrom-NSPFortiGateSection -Path $fixture -Section 'vpn ipsec phase2-interface' -UsedByPolicy)
Assert-Equal $usedPhase2.Count 1 'Used phase2 follows phase1'
Assert-Equal $usedPhase2[0].Name 'Tunnel-VPN-P2' 'Used phase2 name'

$work = Join-Path ([IO.Path]::GetTempPath()) ('NSPFortiGate_' + [guid]::NewGuid().ToString('N'))
try {
    # Export writes one file per section plus the access report.
    $written = @(Export-NSPFortiGateCsv -Path $fixture -OutputDirectory $work -Prefix 'T' -UsedByPolicy)
    Assert-Equal $written.Count 12 'Exported file count'
    Assert-Equal @(Import-Csv -LiteralPath (Join-Path $work 'T_firewall-address.csv')).Count 4 'Exported filtered addresses'
    Assert-Equal @(Import-Csv -LiteralPath (Join-Path $work 'T_policy-access.csv')).Count 2 'Exported access report'
    Assert-Equal @(Get-Content -LiteralPath (Join-Path $work 'T_user-radius.csv') | Select-String 'exampleonly').Count 0 'No secret in export'

    # Terminal wrap at a fixed width is rejoined wherever it lands: mid-word,
    # on a quote, on a space inside a name, or on the space between names.
    $expected = (1..12 | ForEach-Object { 'Service Name {0:00}' -f $_ }) -join '|'
    $long = '        set member ' + ((1..12 | ForEach-Object { '"Service Name {0:00}"' -f $_ }) -join ' ')
    $wrapPath = Join-Path $work 'wrapped.txt'
    foreach ($width in 80..120) {
        $wrapped = New-Object System.Collections.Generic.List[string]
        $wrapped.Add('config firewall service group')
        $wrapped.Add('    edit "Wrapped_Group"')
        for ($i = 0; $i -lt $long.Length; $i += $width) { $wrapped.Add($long.Substring($i, [Math]::Min($width, $long.Length - $i))) }
        $wrapped.Add('    next')
        $wrapped.Add('end')
        [IO.File]::WriteAllLines($wrapPath, $wrapped)
        $members = @(ConvertFrom-NSPFortiGateConfig -Path $wrapPath)[0].Entries[0].Settings['member']
        Assert-Equal ($members -join '|') $expected "Wrapped members at width $width"
    }

    # Printable VPN report: sheets, cross-references, nested expansion, encoding.
    $reportPath = Join-Path $work 'report.html'
    $report = @(Export-NSPFortiGateVpnReport -Path $fixture -Tunnel 'Tunnel-VPN' -OutputPath $reportPath)
    Assert-Equal (($report | ForEach-Object Extension) -join ',') '.html,.xlsx' 'Report writes HTML and Excel'
    $rawHtml = [IO.File]::ReadAllText($report[0].FullName)
    Assert-Equal ($rawHtml -match '<td>Server_<wbr>Services</td>') $true 'Cells offer line breaks after underscores'
    # Assertions below match cell text, so drop the break hints.
    $html = $rawHtml -replace '<wbr>', ''
    Assert-Equal ([regex]::Matches($html, 'class="sheet"').Count) 9 'Report sheet count'
    Assert-Equal ([regex]::Matches($html, 'class="todo"').Count) 4 'NPS and AD sheets are placeholders without their sources'
    Assert-Equal ($html -match 'EXAMPLE-FW VPN access: Tunnel-VPN') $true 'Report title from prompt hostname'
    Assert-Equal ($html -match '<td>vpn-staff</td>') $true 'Report VSA'
    Assert-Equal ($html -match 'rowspan="3">Server_Services</td>') $true 'Report service group spans its members'
    Assert-Equal ($html -match '<td>Remote_Services</td>') $true 'Report nested group via'
    Assert-Equal ($html -match '<td>NOT Server_A</td>') $true 'Report excluded member'
    Assert-Equal ($html -match 'Tunnel client pool') $true 'Report tunnel usage'
    Assert-Equal ($html -match '<td>OU=vpn-staff</td>') $true 'Report peer subject'
    Assert-Equal ($html -match 'Staff &quot;server&quot; access') $true 'Report HTML encoding'
    Assert-Equal ($html -match 'exampleonly') $false 'Report has no secrets'

    # With NPS and AD sources: every sheet filled, cross-linked, and checked.
    $npsFixture = Join-Path $PSScriptRoot 'Fixtures\NPS.ias.sample.xml'
    $adFixture = Join-Path $PSScriptRoot 'Fixtures\ADInventory.sample.json'
    $data = & (Get-Module NSP.FortiGate) { param($f, $n, $a) Get-NSPFortiGateVpnReportData -Path $f -Tunnel 'Tunnel-VPN' -NpsConfig $n -AdInventory $a } $fixture $npsFixture $adFixture
    Assert-Equal @($data.Sheets | Where-Object Placeholder).Count 0 'No placeholders with all sources'
    $npsRows = @($data.Sheets[5].Rows)
    Assert-Equal "$($npsRows[0]['Order']) $($npsRows[0]['NPS policy'])" '1 RADIUS - Contractors' 'NPS policies in Order'
    Assert-Equal $npsRows[0]['FortiGate user group'] "(no match: VPN_Staff expects 'vpn-staff')" 'NPS VSA with a case difference'
    $staffRow = @($npsRows | Where-Object { $_['NPS policy'] -eq 'RADIUS - Staff' })[0]
    Assert-Equal $staffRow['Conditions'] "RADIUS client 192.0.2.1`nMember of: VPN_Staff_AD" 'NPS conditions with SID named from AD'
    Assert-Equal $staffRow['Unlocks (this tunnel)'] "#20 VPN to Servers`n#10 Blocked Legacy (disabled)" 'NPS VSA to firewall policies'
    Assert-Equal @($npsRows | Where-Object { $_['NPS policy'] -eq 'RADIUS - Retired' })[0]['_class'] 'disabled' 'Disabled NPS policy marked'
    Assert-Equal @($data.Sheets[1].Rows)[0]['Sent by NPS policy'] '2. RADIUS - Staff' 'User group names the NPS policy sending its VSA'
    Assert-Equal @($data.Sheets[4].Rows)[0]['Issued by template'] 'NSPIKEv2Staff' 'Peer traced to the template stamping its OU'
    $adRows = @($data.Sheets[6].Rows)
    Assert-Equal $adRows[0]['Group'] 'Contractors_AD' 'AD groups ordered by the NPS policy they satisfy'
    $staffAd = @($adRows | Where-Object { $_['Group'] -eq 'VPN_Staff_AD' })
    Assert-Equal $staffAd[0]['Role'] "NPS policy 2. RADIUS - Staff`nNPS policy 3. RADIUS - Retired`nAuto-enrolls NSPIKEv2Staff" 'AD group roles'
    Assert-Equal $staffAd[0]['Users (all levels)'] '3 (1 disabled)' 'AD recursive user count'
    Assert-Equal @($staffAd | Where-Object { $_['Member'] -eq 'bob' })[0]['Account'] 'disabled' 'Disabled member flagged'
    $templateRow = @($data.Sheets[7].Rows)[0]
    Assert-Equal $templateRow['FortiGate peer (this tunnel)'] 'Peer_Staff (Staff_Peers)' 'Template OU stamp to tunnel peer'
    Assert-Equal $templateRow['Enroll only'] '' 'Admin principals and auto-enroll groups left out of Enroll only'
    $access = @($data.Sheets[8].Rows | Where-Object { $_['NPS policy'] -eq 'RADIUS - Staff' })[0]
    Assert-Equal $access['Also match an earlier policy'] '2 get policy 1. RADIUS - Contractors instead (loses vpn-staff: no VPN_Staff): alice, carol' 'Users shadowed by an earlier NPS policy, with what they lose'
    $staffRules = @($data.Sheets[8].Rows | Where-Object { $_['NPS policy'] -eq 'RADIUS - Staff' })
    Assert-Equal (($staffRules | ForEach-Object { $_['Firewall rule'] }) -join '|') '#20 VPN to Servers|#10 Blocked Legacy (disabled)' 'Effective access: one row per firewall rule, in evaluation order'
    Assert-Equal $staffRules[1]['_class'] 'disabled' 'Effective access: disabled rule marked'
    Assert-Equal ($staffRules[0]['Destination'] -like 'Server_Group: *NOT Server_A*') $true 'Effective access: destination group expanded in place'
    Assert-Equal ($staffRules[0]['Services'] -like 'Server_Services: *') $true 'Effective access: services expanded in place'
    Assert-Equal $staffRules[0]['Action'] 'accept' 'Effective access: rule action'
    Assert-Equal @($data.Checks | Where-Object { $_ -like "*sends VSA 'vpn-contractors'*" }).Count 1 'Check: VSA without a FortiGate group'
    Assert-Equal @($data.Checks | Where-Object { $_ -like "*'RADIUS - Staff': 2 user(s) (alice, carol) match policy 1. RADIUS - Contractors first and so are not placed in VPN_Staff*" }).Count 1 'Check: shadowed users losing a tunnel group'
    # Same shadowing, but the only rule using the lost group is disabled: no access lost, no check.
    $disabledFixture = Join-Path $work 'disabled-policy.txt'
    [IO.File]::WriteAllText($disabledFixture, ([IO.File]::ReadAllText($fixture) -replace '(?m)^(    edit 20\r?\n)', "`$1        set status disable`r`n"))
    $quiet = & (Get-Module NSP.FortiGate) { param($f, $n, $a) Get-NSPFortiGateVpnReportData -Path $f -Tunnel 'Tunnel-VPN' -NpsConfig $n -AdInventory $a } $disabledFixture $npsFixture $adFixture
    Assert-Equal @($quiet.Checks | Where-Object { $_ -like '*are not placed in*' }).Count 0 'No shadow check when the lost group only serves disabled rules'
    Assert-Equal (@($quiet.Sheets[8].Rows | Where-Object { $_['NPS policy'] -eq 'RADIUS - Staff' })[0]['Also match an earlier policy']) '2 get policy 1. RADIUS - Contractors instead (loses vpn-staff, which unlock no enabled rule on this tunnel): alice, carol' 'Shadow text when only disabled rules are affected'
    Assert-Equal @($data.Sheets[8].Rows | Where-Object { $_['NPS policy'] -eq 'RADIUS - Retired' }).Count 0 'Disabled NPS policies are not in effective access'
    # A PSK tunnel (no certificate peers): peer and template sheets say "not applicable", no template checks.
    $pskFixture = Join-Path $work 'psk-tunnel.txt'
    [IO.File]::WriteAllText($pskFixture, ([IO.File]::ReadAllText($fixture) -replace '(?m)^\s*set (peergrp|authmethod|peertype|certificate) .*\r?\n', ''))
    $psk = & (Get-Module NSP.FortiGate) { param($f, $n, $a) Get-NSPFortiGateVpnReportData -Path $f -Tunnel 'Tunnel-VPN' -NpsConfig $n -AdInventory $a } $pskFixture $npsFixture $adFixture
    Assert-Equal $psk.Sheets[4].Empty 'Not applicable: tunnel Tunnel-VPN authenticates with a pre-shared key, not certificates.' 'PSK tunnel: peer groups not applicable'
    Assert-Equal "$(@($psk.Sheets[7].Rows).Count) $($psk.Sheets[7].Empty -like 'Not applicable*') $([bool]$psk.Sheets[7].Placeholder)" '0 True False' 'PSK tunnel: certificate templates not applicable'
    Assert-Equal @($psk.Checks | Where-Object { $_ -match 'template|TameMyCerts' }).Count 0 'PSK tunnel: no certificate template checks'
    Assert-Equal $psk.Facts.Contains('Certificate') $false 'PSK tunnel: unset cover facts left off'
    Assert-Equal @($psk.Sheets[8].Rows).Count @($data.Sheets[8].Rows).Count 'PSK tunnel: effective access unchanged'
    Assert-Equal @($data.Checks | Where-Object { $_ -like "*'NSPIKEv2Contractors' auto-enrolls*no TameMyCerts OU stamp*" }).Count 1 'Check: template without OU stamp'
    Assert-Equal @($data.Checks | Where-Object { $_ -like '1 TameMyCerts policy file(s) match no certificate template in AD: NSPIKEv2Retired (OU=vpn-retired)*' }).Count 1 'Check: TameMyCerts policy without a template'
    Assert-Equal @($data.Sheets[7].Notes | Where-Object { $_ -like '*no certificate template of that name in AD: NSPIKEv2Retired*' }).Count 1 'Template sheet notes the orphan TameMyCerts policy'
    # RADIUS clients (never their secrets) and the addresses the FortiGate sends RADIUS from.
    Assert-Equal $data.NpsFacts['RADIUS clients'] 'Example-FW (192.0.2.1)' 'NPS server: RADIUS clients from ias.xml'
    Assert-Equal @($data.Checks | Where-Object { $_ -like '*sends RADIUS from*' }).Count 0 'No RADIUS source check without a source address'
    $inModule = { param($Block, $Arguments) & (Get-Module NSP.FortiGate) $Block @Arguments }
    Assert-Equal (& $inModule { param($i, $a) Test-NSPFortiGateAddressMatch -Ip $i -Address $a } @('10.99.4.5', '10.99.0.0/16')) $true 'Address inside a RADIUS client range'
    Assert-Equal (& $inModule { param($i, $a) Test-NSPFortiGateAddressMatch -Ip $i -Address $a } @('10.98.4.5', '10.99.0.0/16')) $false 'Address outside a RADIUS client range'
    Assert-Equal (& $inModule { param($i, $a) Test-NSPFortiGateAddressMatch -Ip $i -Address $a } @('10.0.0.1', '0.0.0.0/0')) $true '/0 matches everything'
    $sourceIpFixture = Join-Path $work 'radius-source-ip.txt'
    [IO.File]::WriteAllText($sourceIpFixture, ([IO.File]::ReadAllText($fixture) -replace '(?m)^(\s*)set nas-ip 192\.0\.2\.1', "`$1set nas-ip 192.0.2.1`r`n`$1set source-ip 198.51.100.7"))
    $srcData = & $inModule { param($f, $n) Get-NSPFortiGateVpnReportData -Path $f -Tunnel 'Tunnel-VPN' -NpsConfig $n -RadiusSourceIp '192.0.2.1' } @($sourceIpFixture, $npsFixture)
    Assert-Equal @($srcData.Checks | Where-Object { $_ -like "The FortiGate sends RADIUS from 198.51.100.7 (source-ip of RADIUS server 'RADIUS-1'), which is not a RADIUS client*" }).Count 1 "Check: a RADIUS server's source-ip that isn't an NPS client"
    Assert-Equal @($srcData.Checks | Where-Object { $_ -like '*sends RADIUS from 192.0.2.1*' }).Count 0 'A given source address that is a client raises no check'
    $disabledNps = Join-Path $work 'ias-disabled-client.xml'
    [IO.File]::WriteAllText($disabledNps, ([IO.File]::ReadAllText($npsFixture) -replace '(<IP_Address [^>]*>192\.0\.2\.1</IP_Address>)', '$1<Radius_Client_Enabled xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="boolean">0</Radius_Client_Enabled>'))
    $offData = & $inModule { param($f, $n) Get-NSPFortiGateVpnReportData -Path $f -Tunnel 'Tunnel-VPN' -NpsConfig $n -RadiusSourceIp '192.0.2.1' } @($fixture, $disabledNps)
    Assert-Equal @($offData.Checks | Where-Object { $_ -like "*sends RADIUS from 192.0.2.1 (given as the RADIUS source address), but its RADIUS client 'Example-FW' is disabled*" }).Count 1 'Check: the RADIUS client is disabled'
    Assert-Equal $offData.NpsFacts['RADIUS clients'] 'Example-FW (192.0.2.1, disabled)' 'Disabled RADIUS client marked on the cover'
    $factsReport = @(Export-NSPFortiGateVpnReport -Path $fixture -Tunnel 'Tunnel-VPN' -NpsConfig $npsFixture -NpsFacts ([ordered]@{ 'Server' = 'NPS01 (example.com)'; 'NPS Extension' = '1.2.2893.1'; 'Blank' = '' }) -OutputPath (Join-Path $work 'facts.html'))
    $factsHtml = [IO.File]::ReadAllText($factsReport[0].FullName)
    Assert-Equal ($factsHtml -match '<h2>NPS server</h2><dl><dt>Server</dt><dd>NPS01 \(example\.com\)</dd><dt>NPS Extension</dt><dd>1\.2\.2893\.1</dd><dt>RADIUS clients</dt>') $true 'Cover: NPS server facts in order, then RADIUS clients'
    Assert-Equal ($factsHtml -match '<dt>Blank</dt>') $false 'Cover: blank NPS facts left off'
    $full = @(Export-NSPFortiGateVpnReport -Path $fixture -Tunnel 'Tunnel-VPN' -NpsConfig $npsFixture -AdInventory $adFixture -OutputPath $reportPath)
    Assert-Equal ([IO.File]::ReadAllText($full[0].FullName) -match 'exampleonly') $false 'NPS client secret never reaches the report'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($full[1].FullName)
    try {
        $parts = @($zip.Entries | Where-Object FullName -like 'xl/worksheets/*')
        Assert-Equal $parts.Count 10 'Workbook has About plus nine sheet tabs'
        foreach ($entry in $zip.Entries) {
            $reader = New-Object IO.StreamReader($entry.Open())
            try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
            [xml]$null = $text
            Assert-Equal ($text -match 'exampleonly') $false "No secret in $($entry.FullName)"
        }
    } finally { $zip.Dispose() }

    try {
        Export-NSPFortiGateVpnReport -Path $fixture -Tunnel 'No-Such-Tunnel' -OutputPath $reportPath | Out-Null
        throw 'Unknown tunnel should fail.'
    } catch {
        if ($_.Exception.Message -eq 'Unknown tunnel should fail.') { throw }
    }

    # A configuration backup is never wrap-repaired (a certificate line at the "wrap width" stays
    # its own line) and names the device from 'config system global'.
    $backupPath = Join-Path $work 'backup.conf'
    $certLine = 'A' * 90
    [IO.File]::WriteAllLines($backupPath, @(
        '#config-version=FG100F-7.4.2-FW-build2571-240101:opmode=0:vdom=0:user=admin', '#conf_file_ver=1', '#buildno=2571',
        'config system global', '    set hostname "EXAMPLE-BACKUP"', 'end',
        'config vpn certificate local', '    edit "Example"', ('        set certificate "-----BEGIN CERTIFICATE-----' + ('B' * 50)), $certLine, '-----END CERTIFICATE-----"', '    next', 'end'
    ))
    $backupTree = @(ConvertFrom-NSPFortiGateConfig -Path $backupPath)
    $certificate = @($backupTree | Where-Object Path -eq 'vpn certificate local')[0].Entries[0].Settings['certificate'][0]
    Assert-Equal ($certificate -split "`n").Count 3 'Backup multi-line value keeps its lines (no wrap repair)'
    Assert-Equal ($certificate -split "`n")[1] $certLine 'Backup certificate line intact'
    # A real backup has no CLI prompt lines, so leave the fixture's out.
    [IO.File]::AppendAllLines($backupPath, [string[]]@(Get-Content -LiteralPath $fixture | Where-Object { $_ -notmatch '^EXAMPLE-FW' }))
    $backupData = & (Get-Module NSP.FortiGate) { param($p) Get-NSPFortiGateVpnReportData -Path $p -Tunnel 'Tunnel-VPN' } $backupPath
    Assert-Equal $backupData.DeviceName 'EXAMPLE-BACKUP' 'Device name from a backup hostname'
    Assert-Equal $backupData.PolicyCount 2 'Backup file feeds the report on its own'

    # Multi-VDOM layout: sections under config vdom / edit <name> carry the VDOM.
    $vdomPath = Join-Path $work 'vdom.txt'
    [IO.File]::WriteAllLines($vdomPath, @(
        'config vdom', 'edit root', 'config firewall address', '    edit "Inside"',
        '        set subnet 192.0.2.0 255.255.255.0', '    next', 'end', 'next', 'end'
    ))
    $vdomRows = @(ConvertFrom-NSPFortiGateSection -Path $vdomPath -Section 'firewall address')
    Assert-Equal $vdomRows[0].Vdom 'root' 'VDOM column'
    Assert-Equal $vdomRows[0].Summary '192.0.2.0/24' 'VDOM address summary'

    # Multi-line quoted value keeps its line break.
    $multiPath = Join-Path $work 'multi.txt'
    [IO.File]::WriteAllLines($multiPath, @('config firewall address', '    edit "Note"', '        set comment "line one', 'line two"', '    next', 'end'))
    Assert-Equal @(ConvertFrom-NSPFortiGateSection -Path $multiPath -Section 'firewall address')[0].Comment "line one`nline two" 'Multi-line quoted value'

    # Tokenizer rules (the batch fast path and the character walk must agree).
    $tokenCases = [ordered]@{
        'set a "b c" d'                  = 'set|a|b c|d'
        'set x ab"c d"e f'               = 'set|x|abc de|f'
        'set dn "CN=Doe\, John,DC=x"'    = 'set|dn|CN=Doe\, John,DC=x'
        'set c "say \"hi\" \\ ok"'       = 'set|c|say "hi" \ ok'
        'set e ""'                       = 'set|e|'
        'set f "a""b" "c"'               = 'set|f|ab|c'
        "`tset`tg  h "                   = 'set|g|h'
    }
    foreach ($case in $tokenCases.Keys) {
        $batch = & (Get-Module NSP.FortiGate) { param($t) (Split-NSPFortiGateLineBatch -Text $t)[0] -join '|' } $case
        $walk = & (Get-Module NSP.FortiGate) { param($t) (Split-NSPFortiGateToken -Text $t).Tokens -join '|' } $case
        Assert-Equal $batch $tokenCases[$case] "Tokens of [$case]"
        Assert-Equal $walk $tokenCases[$case] "Split-NSPFortiGateToken agrees on [$case]"
    }
    Assert-Equal (& (Get-Module NSP.FortiGate) { $null -eq (Split-NSPFortiGateLineBatch -Text 'set a "open')[0] }) $true 'An open quote is left for the multi-line path'

    # Multi-line values with escapes, a stray quote outside a value, and a value left open at the end.
    $edgePath = Join-Path $work 'edge.txt'
    [IO.File]::WriteAllLines($edgePath, @(
        'FW01 # show vpn certificate ca', 'config vpn certificate ca', '    edit "CA_1"',
        '        set ca "-----BEGIN CERTIFICATE-----', 'AAAA\"BBBB', '-----END CERTIFICATE-----"', '        set comments "two', 'lines" extra', '    next',
        '    edit "Odd"', '        comment "not a set line', '        set range "x"', '    next', 'end',
        'FW01 "prompt # show system global', 'config system global', '    set hostname "FW01"', '    set alias "open at the end', '    here'
    ))
    $edgeOutput = @(ConvertFrom-NSPFortiGateConfig -Path $edgePath 3>&1)
    $edgeWarnings = @($edgeOutput | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
    $edgeTree = @($edgeOutput | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
    $ca = $edgeTree[0].Entries[0].Settings
    Assert-Equal $ca['ca'][0] "-----BEGIN CERTIFICATE-----`nAAAA`"BBBB`n-----END CERTIFICATE-----" 'Multi-line value unescapes \" inside it'
    Assert-Equal ($ca['comments'] -join '|') "two`nlines|extra" 'A multi-line value followed by another token'
    Assert-Equal @($edgeTree[0].Entries[1].Settings['range'])[0] 'x' 'A stray quote on a non-set line does not swallow the next line'
    Assert-Equal @($edgeTree[1].Settings['hostname'])[0] 'FW01' 'A quote in a prompt does not open a value'
    Assert-Equal @($edgeTree[1].Settings['alias'])[0] "open at the end`n    here" 'A value left open at the end keeps its text'
    Assert-Equal @($edgeWarnings | Where-Object { "$_" -like 'Unterminated quoted value starting at line 18*' }).Count 1 'A value left open at the end is warned about'
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

try {
    $noPolicy = Join-Path ([IO.Path]::GetTempPath()) ('NSPFortiGate_' + [guid]::NewGuid().ToString('N') + '.txt')
    [IO.File]::WriteAllLines($noPolicy, @('config firewall address', '    edit "A"', '    next', 'end'))
    try {
        ConvertFrom-NSPFortiGateSection -Path $noPolicy -Section 'firewall address' -UsedByPolicy | Out-Null
        throw 'UsedByPolicy without policies should fail.'
    } finally {
        Remove-Item -LiteralPath $noPolicy -Force -ErrorAction SilentlyContinue
    }
} catch {
    if ($_.Exception.Message -eq 'UsedByPolicy without policies should fail.') { throw }
}

"$($PSVersionTable.PSVersion): NSP.FortiGate smoke checks passed."
