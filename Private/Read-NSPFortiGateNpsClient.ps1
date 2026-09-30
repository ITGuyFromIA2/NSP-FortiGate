function Read-NSPFortiGateNpsClient {
    <#
    .SYNOPSIS
        Reads the RADIUS clients (name, address, enabled) from an NPS ias.xml.
    .DESCRIPTION
        Only IP_Address and Radius_Client_Enabled are read. Shared_Secret is never read, so a
        secret can't reach the report. Returns nothing when the file has no Clients node.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    [xml]$config = Get-Content -LiteralPath $resolved -Raw
    $ias = $config.Root.Children.Microsoft_Internet_Authentication_Service.Children
    if (-not $ias) { return }
    # The live ias.xml nests Clients under Protocols\Microsoft_Radius_Protocol; some exports put it
    # directly under the service node.
    $clients = $ias.Protocols.Children.Microsoft_Radius_Protocol.Children.Clients.Children
    if (-not $clients) { $clients = $ias.Clients.Children }
    if (-not $clients) { return }
    foreach ($node in $clients.ChildNodes) {
        if ($node.NodeType -ne 'Element') { continue }
        $enabled = [string]$node.Properties.Radius_Client_Enabled.'#text'
        [pscustomobject]@{
            Name = [string]$node.name
            Address = [string]$node.Properties.IP_Address.'#text'
            # Absent means enabled: older exports omit the property.
            Enabled = $enabled -ne '0'
        }
    }
}
