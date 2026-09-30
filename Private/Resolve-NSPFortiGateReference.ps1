function Resolve-NSPFortiGateReference {
    <#
    .SYNOPSIS
        Resolves a name a policy references, following what it depends on.
    .DESCRIPTION
        Address and service groups are expanded to their leaf objects; each
        leaf's Via lists the groups passed through and Excluded marks leaves
        reached through an address group's exclude-member. Other objects are
        returned as themselves; their related references (a user group's
        members and match servers, a tunnel's client pool and peer group) are
        walked, and the resolved ones are attached as Related.

        Every object reached is added to -Used as an object key, which is what
        Export-NSPFortiGateCsv -UsedByPolicy filters on. A name found in no
        loaded section comes back with Missing set, unless it is a builtin or
        its kind is not reported. Lookup tries the policy's VDOM, then
        'global', then no VDOM (captures taken inside a VDOM context carry none).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Index,
        [Parameter(Mandatory)][ValidateSet('Address', 'Service', 'User', 'Interface')][string]$Kind,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [AllowEmptyString()][string]$Vdom = '',
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Used,
        [string[]]$Via = @(),
        [switch]$Excluded
    )

    $kinds = Get-NSPFortiGateReferenceKind
    $found = $null
    foreach ($path in $kinds[$Kind].Sections) {
        foreach ($scope in @($Vdom, 'global', '') | Select-Object -Unique) {
            $dictionary = $Index["$scope`t$path"]
            $entry = $null
            if ($null -ne $dictionary -and $dictionary.TryGetValue($Name, [ref]$entry)) {
                $found = @{ Path = $path; Vdom = $scope; Entry = $entry }
                break
            }
        }
        if ($found) { break }
    }

    $leaf = [ordered]@{ Name = $Name; Kind = $Kind; Path = $null; Vdom = $Vdom; Entry = $null; Missing = $false; Excluded = [bool]$Excluded; Via = $Via; Related = @() }
    if (-not $found) {
        $leaf.Missing = $kinds[$Kind].ReportMissing -and $kinds[$Kind].Builtin -notcontains $Name
        return [pscustomobject]$leaf
    }

    [void]$Used.Add((Get-NSPFortiGateObjectKey -Vdom $found.Vdom -Path $found.Path -Name $Name))
    $leaf.Path = $found.Path
    $leaf.Vdom = $found.Vdom
    $leaf.Entry = $found.Entry
    $settings = $found.Entry.Settings

    $group = $kinds.Groups[$found.Path]
    if ($group) {
        # A group already on the current path is a loop; stop rather than recurse forever.
        if ($Via -contains $Name) { return }
        foreach ($key in $group.Keys) {
            if (-not $settings.Contains($key)) { continue }
            foreach ($member in $settings[$key]) {
                Resolve-NSPFortiGateReference -Index $Index -Kind $group[$key] -Name $member -Vdom $found.Vdom -Used $Used -Via ($Via + $Name) -Excluded:($Excluded -or $key -eq 'exclude-member')
            }
        }
        return
    }

    $related = $kinds.Related[$found.Path]
    # Walked on every visit so each policy sees its own unresolved names; a loop stops at the repeat.
    if ($related -and $Via -notcontains $Name) {
        $leaf.Related = @(
            foreach ($key in $related.Keys) {
                if (-not $settings.Contains($key)) { continue }
                foreach ($member in $settings[$key]) {
                    Resolve-NSPFortiGateReference -Index $Index -Kind $related[$key] -Name $member -Vdom $found.Vdom -Used $Used -Via ($Via + $Name)
                }
            }
            foreach ($match in @($found.Entry.Sections | Where-Object Path -eq 'match')) {
                foreach ($rule in $match.Entries) {
                    if (-not $rule.Settings.Contains('server-name')) { continue }
                    foreach ($server in $rule.Settings['server-name']) {
                        Resolve-NSPFortiGateReference -Index $Index -Kind User -Name $server -Vdom $found.Vdom -Used $Used -Via ($Via + $Name)
                    }
                }
            }
        )
    }
    [pscustomobject]$leaf
}
