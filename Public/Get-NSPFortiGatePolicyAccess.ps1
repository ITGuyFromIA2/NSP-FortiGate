function Get-NSPFortiGatePolicyAccess {
    <#
    .SYNOPSIS
        Documents who each firewall policy lets reach what, with references resolved.
    .DESCRIPTION
        Load the policy capture together with the captures it refers to
        (user groups, RADIUS/LDAP servers, services and service groups,
        addresses and address groups, IPsec phase1/phase2). Each policy row
        then carries, besides the names written in the policy:

          Vpn            the tunnel behind a VPN interface, summarized
          GroupMatch     each user group's server-side match, "server: group"
          GroupMembers   each user group's members (servers or local users)
          SrcAddrDetail  addresses expanded through nested groups to CIDR,
          DstAddrDetail  ranges, or FQDNs; "NOT:" marks a negated field
          ServiceDetail  services expanded through groups to protocol/port
          Unresolved     referenced names defined in none of the captures,
                         which tells you which capture is still missing

        Sequence is the order in the capture, which is the evaluation order.
    .PARAMETER Path
        Capture files, parsed together.
    .PARAMETER InputObject
        CLI text from the pipeline, for example Get-Clipboard.
    .PARAMETER Delimiter
        Joins multiple values in one cell. Use "`n" for line breaks in Excel.
    .EXAMPLE
        Get-NSPFortiGatePolicyAccess -Path .\policies.txt, .\groups.txt, .\radius.txt, .\services.txt, .\servicegroups.txt |
            Export-Csv .\vpn-access.csv -NoTypeInformation
    .EXAMPLE
        Get-NSPFortiGatePolicyAccess -Path .\captures\*.txt | Where-Object Unresolved | Select-Object PolicyId, Unresolved
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][ValidateNotNullOrEmpty()][string[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Text')][AllowEmptyString()][string[]]$InputObject,
        [ValidateNotNull()][string]$Delimiter = '; '
    )

    begin { $buffer = New-Object System.Collections.Generic.List[string] }
    process {
        foreach ($text in $InputObject) { $buffer.AddRange([string[]]($text -split '\r?\n')) }
    }
    end {
        $tree = Read-NSPFortiGateInput -Path $Path -Line $buffer.ToArray()
        $analysis = Get-NSPFortiGatePolicyAnalysis -Tree $tree -Delimiter $Delimiter
        if ($analysis.PolicyCount -eq 0) { Write-Warning "No 'config firewall policy' block found in the input." }
        $analysis.Rows
    }
}
