function Read-NSPFortiGateInput {
    <#
    .SYNOPSIS
        Parses one or more files, or buffered pipeline text, into root sections.
    .DESCRIPTION
        Each file is parsed on its own so an incomplete capture cannot pull
        the next file's sections into its last open block. Results from all
        files are combined, which lets separate 'show' captures (policies,
        groups, services, addresses) be analyzed together.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Path,
        [AllowEmptyCollection()][AllowEmptyString()][string[]]$Line
    )

    $roots = [System.Collections.Generic.List[object]]::new()
    if ($Path) {
        foreach ($item in $Path) {
            # Literal first: console capture names often contain [ ] which wildcards would misread.
            $matched = if (Test-Path -LiteralPath $item) { Resolve-Path -LiteralPath $item } else { Resolve-Path -Path $item -ErrorAction Stop }
            foreach ($resolved in $matched) {
                Write-Verbose "Parsing $($resolved.ProviderPath)"
                $roots.AddRange([object[]](Read-NSPFortiGateConfigTree -Line ([IO.File]::ReadAllLines($resolved.ProviderPath))))
            }
        }
    } else {
        $roots.AddRange([object[]](Read-NSPFortiGateConfigTree -Line $Line))
    }
    , $roots.ToArray()
}
