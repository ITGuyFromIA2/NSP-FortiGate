# NSP.FortiGate

Turns FortiGate CLI `show` captures into CSV-ready objects and documents what
firewall policies actually reference: which user groups (and their RADIUS/LDAP
match rules), which tunnels and certificate peers, which addresses, and which
ports, with nested groups resolved.

Captures can be pasted straight from the console. CLI prompts, `--More--`
pager output, `grep -f` `<---` markers, and terminal line wraps (even mid-name,
mid-quote) are handled. Windows PowerShell 5.1 and PowerShell 7 are supported.

## Capturing

Run one `show` per object type and save each console session to a text file.
`show` omits settings still at their default; the named columns below fill the
common defaults back in (use `-NoDefaults` to leave them blank).
`show full-configuration` also works and yields many more columns.

```text
show firewall policy            (or: show firewall policy | grep -f <interface>)
show firewall address
show firewall addrgrp
show firewall service custom
show firewall service group
show user group
show user radius                (and/or: show user ldap)
show user peergrp
show user peer
show vpn ipsec phase1-interface
show vpn ipsec phase2-interface
```

A configuration backup (`.conf`, System > Configuration > Backup; "Password
mask" recommended) can replace all of the captures above. It is recognized by its
`#config-version=` header: terminal-wrap repair is skipped for it, and the device
name comes from `config system global` (`set hostname`) since it has no CLI prompt.

## Documenting VPN access

```powershell
Import-Module .\NSP.FortiGate.psd1

# Everything at once: filtered object CSVs plus the access report.
Export-NSPFortiGateCsv -Path .\captures\*.txt -OutputDirectory .\out -Prefix FGT01 -UsedByPolicy

# Or just the report, one row per policy.
Get-NSPFortiGatePolicyAccess -Path .\captures\*.txt |
    Export-Csv .\out\vpn-access.csv -NoTypeInformation
```

`Get-NSPFortiGatePolicyAccess` columns, beyond the policy's own fields:

| Column | Content |
|---|---|
| `Sequence` | Order in the capture, which is evaluation order (IDs are not) |
| `Vpn` | Tunnel behind a VPN interface: IKE version, dial-up or peer, pool, split tunnel, peer group |
| `VpnPeers` | Certificate peers the tunnel accepts (CA, subject, MFA server) |
| `GroupMatch` | Each user group's server-side match, `server: group` |
| `GroupMembers` | Each user group's members (servers or local users) |
| `SrcAddrDetail`, `DstAddrDetail` | Addresses expanded through nested groups to CIDR, ranges, FQDNs; `NOT` marks exclusions and negation |
| `ServiceDetail` | Services expanded through groups to protocol/port |
| `Unresolved` | Referenced names defined in none of the captures: tells you which capture is missing |

With `-UsedByPolicy`, object sections (addresses, services, users, groups,
servers, peers, tunnels) keep only entries the policies reach, directly or
through groups, tunnels, and user groups. A phase2 is kept when its phase1 is.

## Printable VPN document

```powershell
Export-NSPFortiGateVpnReport -Path .\captures\*.txt -Tunnel 'Dialup-IKEv2' `
    -NpsConfig .\ias.xml -AdInventory .\ADInventory_example.com_20260101_120000.json `
    -OutputPath .\Dialup-IKEv2.html
```

Writes `Dialup-IKEv2.html` and `Dialup-IKEv2.xlsx`. Secrets are never written, but the
report still maps a network's VPN rules, addresses, and AD groups: handle it as
confidential. In the HTML, each sheet
starts on a new printed page (landscape), so the printout can be separated and
cross-referenced. In the workbook, each sheet is its own tab after an About
tab, with the header row frozen and filterable.

The report has a cover followed by nine sheets. The cover lists the tunnel's
settings, the NPS server (with `-NpsConfig`), and a **Checks** list of
mismatches found along the way.

| Sheet | Needs | Content |
|---|---|---|
| 1 Firewall policies | captures | Rules on the tunnel, in evaluation order |
| 2 User groups | captures (+ NPS) | Each group's expected VSA, and which NPS policy sends it |
| 3 Service groups | captures | Expanded to protocol/port |
| 4 Address groups | captures | Expanded to addresses |
| 5 Peer groups | captures (+ AD) | Peer subject match, and the template that stamps it |
| 6 NPS configuration | `-NpsConfig` | Policies in order: conditions, VSAs returned, where each lands |
| 7 AD group membership | `-AdInventory` | Each group's role, nesting, and members |
| 8 Certificate templates | `-AdInventory` | Auto-enroll groups, validity, TameMyCerts OU stamp, matching peer |
| 9 Effective access by AD group | `-NpsConfig` (+ AD) | AD group → NPS policy → VSA → FortiGate group → each firewall rule it unlocks, written out (action, interface, source, destination, services, groups expanded) |

The two extra sources:
- **`-NpsConfig`:** a copy of the NPS server's `C:\Windows\System32\ias\ias.xml`,
  or a `netsh nps export`. Policies, profiles, and each RADIUS client's name,
  address, and enabled state are read. Shared secrets are never read.
- **`-AdInventory`:** a JSON inventory of the VPN's AD groups and certificate
  templates, in the format below. Any read-only collector can produce it.
  `Tests\Fixtures\ADInventory.sample.json` in the repository is a complete example.

Without a source, the sheets that need it print as headed placeholders.

Two optional parameters add to the cover's **NPS server** block:
- **`-RadiusSourceIp`:** the address the FortiGate sends RADIUS from, as NPS sees
  it (the interface facing the NPS server). It is checked against the RADIUS
  clients in `ias.xml`, along with the `set source-ip` of each RADIUS server the
  tunnel's user groups match on. NPS silently drops requests from an address that
  isn't a RADIUS client, so a miss, or a disabled client, is raised as a Check.
- **`-NpsFacts`:** label/value pairs shown first in that block, such as the
  server name or NPS Extension version (`[ordered]@{ Server = 'NPS01' }`).

### AD inventory format (`SchemaVersion` 1)

| Field | Content |
|---|---|
| `SchemaVersion` | `1` (other values are refused) |
| `Generated`, `Domain`, `ComputerName` | When, for which domain, and where it was collected (shown in the report's sources) |
| `Groups[]` | `Name`, `Sid`, `DistinguishedName`, `MemberOf[]` (`Name`, `Sid`), `Members[]` (`Name`, `Class` = `user`/`group`, `Sid`, `Enabled`), `RecursiveUsers[]` (`Name`, `DistinguishedName`, `Enabled`) |
| `Templates[]` | `Name`, `DisplayName`, `ValidityDays`, `RenewalDays`, `EnrolleeSuppliesSubject`, `Enroll[]` / `AutoEnroll[]` (`Name` as `DOMAIN\group`, `Sid`), `PublishedOn[]`, `OuStamp` (the `OU=` value a subject-stamping policy module forces into issued certificates, or `null`) |
| `TameMyCerts` | Optional: `PolicyDirectory`, `Policies[]` (`Template`, `OuValue`) |
| `Sources.GroupPattern` | Optional: name patterns used to pick the groups, e.g. `VPN*` |

Group SIDs are matched against the `USERNTGROUPS` conditions in `ias.xml`, so NPS
policy conditions show group names and the report can tell which users an
earlier policy shadows. Template OU stamps are matched against the tunnel's
certificate peers (`set subject`).

Object sheets have a "Used by" column naming the policies (`#143`) or tunnel
setting that reference each object.

Sheet 9 also shows users an earlier NPS policy *shadows*. NPS stops at the
first matching policy, so a user in two policies' groups gets only the first
policy's VSAs. Print from a browser, or open the HTML in Word to edit.

## Other commands

```powershell
# One section as rows; any section path works, known ones get named columns.
ConvertFrom-NSPFortiGateSection -Path .\groups.txt -Section 'user group'
ConvertFrom-NSPFortiGatePolicy -Path .\policies.txt | Export-Csv .\policies.csv -NoTypeInformation

# Every section in a full backup.
Export-NSPFortiGateCsv -Path .\backup.conf -Section * -OutputDirectory .\dump

# The raw tree, for settings no CSV surfaces; also reads the clipboard.
Get-Clipboard | ConvertFrom-NSPFortiGateConfig
```

Multi-value settings are joined with `; ` by default; pass `-Delimiter "`n"`
for line breaks inside Excel cells. Passwords, pre-shared keys, RADIUS secrets,
and any `ENC` value are written as `<redacted>` unless `-IncludeSecrets` is set.
Multi-VDOM configurations get a `Vdom` column.

## Generating CLI

These return CLI text to review and paste; nothing is sent to a FortiGate.

```powershell
# Address objects plus the group holding them (subnets, hosts, FQDNs; existing objects by name).
New-NSPFortiGateAddressGroupCli -GroupName 'VPN_FileServers' -Member '10.0.0.10', 'files.contoso.com', '10.0.5.0/24'

# One custom service entry, and one VPN-to-LAN policy entry (or its -Reverse mirror).
New-NSPFortiGateServiceCli -Name 'App-8443' -Protocol TCP -Port 8443
New-NSPFortiGatePolicyCli -Name 'Contoso-SMB' -TunnelInterface 'IKEv2_Staff' -InternalInterface 'internal' `
    -TunnelAddress 'IKEv2_Staff_range' -DestinationAddress 'VPN_FileServers' -Service 'SMB' -UserGroup 'VPN_Staff'

# Convert local users to RADIUS: the FortiGate CLI plus a snippet that adds them to AD groups.
# A user group's current members are kept, because 'set member' replaces the whole list.
$inv = Get-NSPFortiGateUserInventory -Path .\backup.conf
$users = @($inv.Users | Where-Object Type -eq 'password' | ForEach-Object Username)
$group = $inv.Groups | Where-Object Name -eq 'SSLVPN_Users'
$out = New-NSPFortiGateUserConversionCli -Usernames $users -TargetType radius -ServerName 'NPS01' `
    -ADGroups 'VPN_Staff' -GroupName $group.Name -ExistingGroupMembers $group.Members
$out.FGT; $out.AD
```

## Adding a section

Every section already exports with its FortiOS setting names. For friendly
column names, defaults, and a computed `Summary`, add an entry to
`Private\Get-NSPFortiGateSchema.ps1` (and a case in
`Private\Get-NSPFortiGateObjectSummary.ps1`). For the new objects to count as
used by policies, list their section and what they reference in
`Private\Get-NSPFortiGateReferenceKind.ps1`.

## Testing

`.\tools\Test-Repo.ps1` checks the manifest, help, and source hygiene, runs
`Tests\Smoke.ps1` under both `powershell.exe` and `pwsh.exe`, and runs
PSScriptAnalyzer when installed. The fixture is invented; see
`Tests\Fixtures\README.md`.
