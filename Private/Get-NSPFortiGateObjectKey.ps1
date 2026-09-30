function Get-NSPFortiGateObjectKey {
    <#
    .SYNOPSIS
        Identity of one configured object: VDOM, section path, and name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()][string]$Vdom = '',
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name
    )

    "$Vdom`t$Path`t$Name"
}
