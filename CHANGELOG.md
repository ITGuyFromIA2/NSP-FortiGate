# Changelog

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
