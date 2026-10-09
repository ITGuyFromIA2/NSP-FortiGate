# Changelog

## 0.3.1 (2026-10-09)

- Release routine: `tools\Publish-ToGallery.ps1` now runs `Publish-NSPModule` from NSP.RepoTools, the checks every NSP module shares (including a client-reference sweep of the Git history). No change to the module itself.

## 0.3.0 (2026-10-08)

- CLI builders, moved here from the NSP IPsec CLI builder so other scripts can use them:
  `New-NSPFortiGateAddressGroupCli` (address objects plus the address group),
  `New-NSPFortiGateServiceCli` (a custom TCP/UDP service entry) and
  `New-NSPFortiGatePolicyCli` (a VPN-to-LAN policy entry or its reverse mirror). Output uses LF
  line endings throughout. A security profile that isn't given is now left out, rather than
  written as `set ... ""`.
- Local-user conversion to RADIUS or LDAP: `Get-NSPFortiGateUserInventory` (users, servers and
  groups with their current members, from a backup or a console capture, multi-VDOM aware) and
  `New-NSPFortiGateUserConversionCli` (the FortiGate CLI that keeps a group's existing members,
  plus a per-user AD group snippet).

## 0.2.1 (2026-09-30)

- Parsing is much faster, with identical output. A 19,000-line configuration
  backup went from 27 s to 1.5 s on Windows PowerShell 5.1, and from 12 s to
  under 2 s on PowerShell 7. The VPN report on it went from 33 s to 4 s.
  - Lines are split by one regex match each, in a single pass over the file,
    instead of a character loop called once per line.
  - A multi-line value (such as a certificate) is no longer re-read from its
    first line each time a line is added.
  - `[type]::new()` replaces `New-Object`, which is a cmdlet call.
    `Write-Verbose` is skipped unless verbose output is on.
- More tests for the tokenizer and multi-line values: escapes, stray quotes,
  quotes in prompts, and a value left open at the end of the input.

## 0.2.0 (2026-09-30)

- The VPN report's cover has an **NPS server** block: the RADIUS clients in
  `ias.xml` (name, address, disabled), after any `-NpsFacts` label/value pairs
  (such as the server name or NPS Extension version). Shared secrets are still
  never read.
- New Check: an address the FortiGate sends RADIUS from that isn't an enabled
  NPS RADIUS client. NPS drops those requests silently. Addresses come from
  `-RadiusSourceIp` and from `set source-ip` on the RADIUS servers the tunnel's
  user groups match on. RADIUS clients defined as a range are honored.
- The workbook's About tab lists the NPS server block as `NPS: <label>` rows.

## 0.1.0 (2026-09-30)

First public release. Reads FortiGate configuration backups and CLI console
captures:

- Config tree parser tolerant of prompts, pager output, `grep -f` markers,
  terminal line wraps, escaped quotes, multi-line values, and multi-VDOM layout.
- Named CSV layouts for firewall policy, address, address group, service,
  service group, user group, local user, RADIUS, LDAP, peer, peer group, and
  IPsec phase1/phase2; every other section exports with FortiOS names.
- Policy access report resolving tunnels, peers, user group match rules,
  nested address and service groups, and unresolved references.
- `-UsedByPolicy` filtering to the objects the policies reach.
- Secrets redacted by default.
- `Export-NSPFortiGateVpnReport` writes a printable HTML document and an Excel
  workbook (no Excel or extra modules needed). The report has nine sheets, from
  firewall policies through effective access by AD group, plus a Checks list.
  NPS sheets come from `ias.xml` (`-NpsConfig`). AD group tree and certificate
  template sheets come from an AD inventory JSON (`-AdInventory`, format in the README),
  including TameMyCerts OU stamps.
- Effective access by AD group lists each firewall rule a VSA unlocks on its
  own row. The row shows the rule's action, interface, source, destination, and
  services, with address and service groups expanded in place. Merged cells
  nest: NPS policy, then VSA, then rule.
- A PSK/EAP tunnel marks the Peer groups and Certificate templates sheets "not
  applicable" and raises no template checks. Cover facts the tunnel does not
  set are left off.
- A new Check lists TameMyCerts policy files that match no certificate
  template in AD.
