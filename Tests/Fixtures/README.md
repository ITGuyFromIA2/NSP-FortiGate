# Invented format fixtures

`FortiGate.capture.sample.txt` preserves the shape of FortiGate console
captures: CLI prompts between blocks, `grep -f` `<---` markers, escaped quotes,
nested `config match` blocks, `unset` lines, and `ENC` secrets. It chains the
references a VPN policy makes (tunnel, client pool, nested address and service
groups with an exclusion, user group, RADIUS server) and adds unused objects so
filtering can be checked. Every name, address, and secret is invented; addresses
use documentation ranges.

Terminal wrapping and multi-VDOM layout are built inline in `Smoke.ps1`.

`NPS.ias.sample.xml` preserves the `ias.xml` node layout NPS writes: connection
request and network policies with `msNPConstraint`/`msNPSequence`, RADIUS
profiles with Fortinet-Group-Name VSAs in `msRADIUSAnyVSA` hex form, and a RADIUS
client entry with a shared secret, which tests check never reaches any output.

`ADInventory.sample.json` follows the SchemaVersion 1 AD inventory format
(see the main README): groups with SIDs, nesting, and recursive users (including a disabled
account and a user reached through two NPS policies), templates with
Enroll/AutoEnroll principals, and one TameMyCerts OU stamp. All names, SIDs,
and paths are invented.
