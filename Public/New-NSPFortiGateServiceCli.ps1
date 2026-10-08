function New-NSPFortiGateServiceCli {
    <#
    .SYNOPSIS
        One 'config firewall service custom' entry (edit ... next, indented for the block) for a
        TCP, UDP or TCP+UDP port or port range.
    .DESCRIPTION
        Returns the entry only, so several can share one 'config firewall service custom' ... 'end'.
        Lines end in LF.
    .PARAMETER Name
        The service's name.
    .PARAMETER Protocol
        TCP, UDP or TCP+UDP.
    .PARAMETER Port
        A port, a range (8000-8010) or several separated by spaces, as FortiOS takes them.
    .EXAMPLE
        "config firewall service custom`n" + (New-NSPFortiGateServiceCli -Name 'App-8443' -Protocol TCP -Port 8443) + "`nend"
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns CLI text; changes nothing.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('TCP', 'UDP', 'TCP+UDP')][string]$Protocol,
        [Parameter(Mandatory)][ValidatePattern('^\d{1,5}(-\d{1,5})?( \d{1,5}(-\d{1,5})?)*$')][string]$Port
    )
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("    edit $(ConvertTo-NSPFortiGateCliName $Name)")
    if ($Protocol -ne 'UDP') { $lines.Add("        set tcp-portrange $Port") }
    if ($Protocol -ne 'TCP') { $lines.Add("        set udp-portrange $Port") }
    $lines.Add('    next')
    $lines -join "`n"
}
