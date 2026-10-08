function Get-NSPFortiGateUserInventory {
    <#
    .SYNOPSIS
        Local users, RADIUS and LDAP servers, and user groups (with their current members) from a
        FortiGate backup or console capture - what converting local users to RADIUS or LDAP needs.
    .DESCRIPTION
        The input is a full configuration backup (.conf) or a console capture of 'show user local',
        optionally with 'show user group', 'show user radius' and 'show user ldap'. Multi-VDOM backups
        work: every row carries the VDOM it came from.

        Returns one object:
          Path, Kind     'backup' when the first line is '#config-version=', else 'capture'
          DeviceName     hostname from 'config system global', or from the capture's prompt
          Vdoms          VDOMs that hold local users (empty when not multi-VDOM)
          Users          Username, Type (password, radius, ldap, ...), Disabled, Server, Vdom
          RadiusServers  Name, Address, Vdom
          LdapServers    Name, Address, Vdom
          Groups         Name, Members, Matched (matches RADIUS/LDAP group names), Vdom
    .PARAMETER Path
        The backup or capture file.
    .EXAMPLE
        (Get-NSPFortiGateUserInventory -Path .\FGT-backup.conf).Users | Where-Object Type -eq 'password'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    $tree = @(ConvertFrom-NSPFortiGateConfig -Path $Path)
    $first = [string](Get-Content -LiteralPath $Path -TotalCount 1)
    $kind = if ($first -match '^#config-version=') { 'backup' } else { 'capture' }
    $value = { param($Entry, [string]$Key, [string]$Default = '') if ($Entry.Settings.Contains($Key)) { [string](@($Entry.Settings[$Key])[0]) } else { $Default } }

    # Every section, however deep: a multi-VDOM backup nests each VDOM's sections under the entries
    # of 'config vdom' (and the parser stamps them with that VDOM).
    $allSections = [Collections.Generic.List[object]]::new()
    $pending = [Collections.Generic.Queue[object]]::new()
    foreach ($section in $tree) { $pending.Enqueue($section) }
    while ($pending.Count) {
        $section = $pending.Dequeue()
        $allSections.Add($section)
        foreach ($child in $section.Sections.ToArray()) { $pending.Enqueue($child) }
        foreach ($entry in $section.Entries.ToArray()) { foreach ($child in $entry.Sections.ToArray()) { $pending.Enqueue($child) } }
    }
    $entriesOf = { param([string]$SectionPath) foreach ($section in @($allSections.ToArray() | Where-Object Path -eq $SectionPath)) { foreach ($entry in $section.Entries.ToArray()) { [pscustomobject]@{ Entry = $entry; Vdom = [string]$section.Vdom } } } }

    $deviceName = ''
    if ($kind -eq 'backup') {
        # 'config system global' holds settings directly, not edit entries.
        $global = @($allSections.ToArray() | Where-Object Path -eq 'system global' | Select-Object -First 1)
        if ($global.Count -and $global[0].Settings.Contains('hostname')) { $deviceName = [string](@($global[0].Settings['hostname'])[0]) }
    } else {
        $prompt = Select-String -LiteralPath $Path -Pattern '^(\S+?)(?: \([^)]*\))? # ' | Select-Object -First 1
        if ($prompt) { $deviceName = $prompt.Matches[0].Groups[1].Value }
    }

    $users = @(foreach ($item in (& $entriesOf 'user local')) {
            $type = (& $value $item.Entry 'type' 'password').ToLowerInvariant()
            [pscustomobject]@{
                Username = $item.Entry.Name
                Type     = $type
                Disabled = (& $value $item.Entry 'status' 'enable') -eq 'disable'
                Server   = if ($type -in 'radius', 'ldap') { & $value $item.Entry "$type-server" } else { '' }
                Vdom     = $item.Vdom
            }
        })
    $servers = {
        param([string]$SectionPath)
        @(foreach ($item in (& $entriesOf $SectionPath)) { [pscustomobject]@{ Name = $item.Entry.Name; Address = & $value $item.Entry 'server'; Vdom = $item.Vdom } })
    }
    $groups = @(foreach ($item in (& $entriesOf 'user group')) {
            $matched = @($item.Entry.Sections.ToArray() | Where-Object Path -eq 'match' | ForEach-Object { $_.Entries.ToArray() }).Count -gt 0
            [pscustomobject]@{ Name = $item.Entry.Name; Members = @($item.Entry.Settings['member'] | Where-Object { $_ }); Matched = $matched; Vdom = $item.Vdom }
        })

    [pscustomobject]@{
        PSTypeName    = 'NSP.FortiGate.UserInventory'
        Path          = $Path
        Kind          = $kind
        DeviceName    = $deviceName
        Vdoms         = @($users | ForEach-Object Vdom | Where-Object { $_ } | Select-Object -Unique)
        Users         = $users
        RadiusServers = @(& $servers 'user radius')
        LdapServers   = @(& $servers 'user ldap')
        Groups        = $groups
    }
}
