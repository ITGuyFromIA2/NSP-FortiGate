function Get-NSPFortiGateIndex {
    <#
    .SYNOPSIS
        Indexes every top-level section's entries by VDOM, path, and name.
    .DESCRIPTION
        Keys are "vdom<TAB>path"; values map entry name to entry. Names are
        case-sensitive, as on FortiOS. A later definition of the same name
        (from a later capture) replaces the earlier one.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Tree)

    $index = @{}
    foreach ($section in (Find-NSPFortiGateSection -Section $Tree -Pattern '*')) {
        $key = "$($section.Vdom)`t$($section.Path)"
        if (-not $index.ContainsKey($key)) { $index[$key] = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal) }
        foreach ($entry in $section.Entries) { $index[$key][$entry.Name] = $entry }
    }
    $index
}
