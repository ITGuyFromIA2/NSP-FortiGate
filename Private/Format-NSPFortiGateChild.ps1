function Format-NSPFortiGateChild {
    <#
    .SYNOPSIS
        Renders nested config blocks (such as 'config match') as one CSV cell.
    .DESCRIPTION
        With -Keys, each nested entry becomes those keys' values joined by
        -Separator ("RADIUS-1: vpn-users"). Without -Keys, each entry becomes
        [name] key=value pairs so nothing is lost. Entries are joined by
        -Delimiter.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()][object[]]$Section = @(),
        [string[]]$Keys,
        [string]$Separator = ': ',
        [string]$Delimiter = '; ',
        [switch]$IncludeSecrets
    )

    $parts = foreach ($child in $Section) {
        $nodes = if ($child.Entries.Count) { $child.Entries } else { @($child) }
        foreach ($node in $nodes) {
            if ($Keys) {
                $values = foreach ($key in $Keys) {
                    if ($node.Settings.Contains($key)) {
                        Format-NSPFortiGateValue -Key $key -Value $node.Settings[$key] -Delimiter ' ' -IncludeSecrets:$IncludeSecrets
                    }
                }
                @($values | Where-Object { $_ }) -join $Separator
            } else {
                $pairs = foreach ($key in $node.Settings.Keys) {
                    $text = Format-NSPFortiGateValue -Key $key -Value $node.Settings[$key] -Delimiter ' ' -IncludeSecrets:$IncludeSecrets
                    if ($text -eq '' -or $text -match '\s') { $text = '"' + $text + '"' }
                    "$key=$text"
                }
                $label = if ($node.PSObject.Properties['Name']) { "[$($node.Name)] " } else { '' }
                $label + ($pairs -join ' ')
            }
        }
    }
    @($parts) -join $Delimiter
}
