function Find-NSPFortiGateSection {
    <#
    .SYNOPSIS
        Finds sections whose path matches any wildcard pattern, at any depth.
    .DESCRIPTION
        The 'vdom' and 'global' wrappers of a multi-VDOM configuration are
        never returned themselves; the search always descends through them.
        A matching section is returned without searching inside it, so '*'
        yields each top-level section rather than every nested block.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Section,
        [Parameter(Mandatory)][string[]]$Pattern
    )

    foreach ($candidate in $Section) {
        $isWrapper = $candidate.Path -eq 'vdom' -or $candidate.Path -eq 'global'
        if (-not $isWrapper -and @($Pattern | Where-Object { $candidate.Path -like $_ }).Count) {
            $candidate
            continue
        }
        $children = New-Object System.Collections.Generic.List[object]
        $children.AddRange($candidate.Sections)
        foreach ($entry in $candidate.Entries) { $children.AddRange($entry.Sections) }
        if ($children.Count) { Find-NSPFortiGateSection -Section $children.ToArray() -Pattern $Pattern }
    }
}
