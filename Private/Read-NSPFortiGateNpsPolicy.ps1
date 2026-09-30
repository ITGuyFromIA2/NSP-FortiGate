function Read-NSPFortiGateNpsPolicy {
    <#
    .SYNOPSIS
        Reads NPS connection request and network policies, with Fortinet VSAs, from ias.xml.
    .DESCRIPTION
        Accepts the live C:\Windows\System32\ias\ias.xml or a 'netsh nps export'
        file (same schema). Only policy and RADIUS profile nodes are read here; the
        RADIUS clients are read by Read-NSPFortiGateNpsClient, which skips their shared secrets.

        Each policy has Type (ConnectionRequest or NetworkPolicy), Sequence,
        Name, Enabled, Conditions (the raw msNPConstraint strings, ANDed),
        GroupSids (from USERNTGROUPS; any one of them satisfies that condition),
        ClientAddresses (from Client-IP-Address matches), and Vsas: the
        Fortinet-Group-Name values the policy's profile returns.

        Fortinet-Group-Name is stored in msRADIUSAnyVSA as hex "01" + vendor
        00003044 (12356) + type "01" + a length byte, followed by the literal
        ASCII name; this is the encoding NPS-Manager writes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    [xml]$config = Get-Content -LiteralPath $resolved -Raw
    $ias = $config.Root.Children.Microsoft_Internet_Authentication_Service.Children
    if (-not $ias) { throw "'$Path' is not an NPS configuration (no Microsoft_Internet_Authentication_Service node)." }
    $profiles = $ias.RadiusProfiles.Children

    foreach ($container in @(@('Proxy_Policies', 'ConnectionRequest'), @('NetworkPolicy', 'NetworkPolicy'))) {
        $nodes = $ias.($container[0]).Children
        if (-not $nodes) { continue }
        $policies = foreach ($node in $nodes.ChildNodes) {
            if ($node.NodeType -ne 'Element') { continue }
            $sequence = 0
            [void][int]::TryParse([string]$node.Properties.msNPSequence.'#text', [ref]$sequence)
            $conditions = @(@($node.Properties.msNPConstraint) | ForEach-Object { $_.'#text' } | Where-Object { $_ })
            $sids = @(foreach ($condition in $conditions) {
                if ($condition -match '^USERNTGROUPS\((.*)\)$') { [regex]::Matches($Matches[1], '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value } }
            })
            $clients = @(foreach ($condition in $conditions) {
                if ($condition -match '^MATCH\("Client-IP-Address=([^"]+)"\)$') { $Matches[1] }
            })
            $vsas = @()
            if ($container[1] -eq 'NetworkPolicy' -and $profiles) {
                $radiusProfile = $profiles.($node.LocalName)
                if ($radiusProfile) {
                    $vsas = @(foreach ($hex in @(@($radiusProfile.Properties.msRADIUSAnyVSA) | ForEach-Object { $_.'#text' } | Where-Object { $_ })) {
                        if ($hex -match '^0100003044(01)[0-9A-Fa-f]{2}(.+)$') { $Matches[2] }
                    })
                }
            }
            [pscustomobject]@{
                Type = $container[1]
                Sequence = $sequence
                Name = [string]$node.name
                Enabled = [string]$node.Properties.Policy_Enabled.'#text' -eq '1'
                Conditions = $conditions
                GroupSids = $sids
                ClientAddresses = $clients
                Vsas = $vsas
            }
        }
        @($policies) | Sort-Object Sequence
    }
}
