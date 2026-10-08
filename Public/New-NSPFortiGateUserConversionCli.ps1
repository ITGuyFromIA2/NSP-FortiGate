function New-NSPFortiGateUserConversionCli {
    <#
    .SYNOPSIS
        Converts FortiGate local users to RADIUS or LDAP authentication: the FortiGate CLI, plus a
        PowerShell snippet that adds the same users to AD groups.
    .DESCRIPTION
        Returns an object with:
          FGT  'config user local' setting each user's type and server; with -GroupName, a
               'config user group' block too. 'set member' replaces a group's whole member list, so
               -ExistingGroupMembers (the group's current members) are kept and the converted users
               are appended, without duplicates (case-insensitive). With -Vdom the whole thing is
               wrapped in 'config vdom' / 'edit <Vdom>' ... 'end'.
          AD   PowerShell that adds each user to every -ADGroups group, one user at a time so a user
               missing from AD doesn't stop the rest; $FailedUsers lists the ones that failed,
               ready to pass back as -DisabledUsernames.
        Lines end in CRLF.
    .PARAMETER Usernames
        The local users to convert.
    .PARAMETER TargetType
        radius or ldap.
    .PARAMETER ServerName
        The RADIUS or LDAP server object on the FortiGate.
    .PARAMETER ADGroups
        AD groups for the AD snippet.
    .PARAMETER DisabledUsernames
        Users that also get 'set status disable' (for example, people who have left). Case-insensitive.
    .PARAMETER GroupName
        FortiGate user group to add the converted users to.
    .PARAMETER ExistingGroupMembers
        The group's current members. Ignored without -GroupName.
    .PARAMETER Vdom
        The VDOM, on a multi-VDOM FortiGate.
    .EXAMPLE
        $inv = Get-NSPFortiGateUserInventory -Path .\FGT-backup.conf
        $users = @($inv.Users | Where-Object Type -eq 'password' | ForEach-Object Username)
        $out = New-NSPFortiGateUserConversionCli -Usernames $users -TargetType radius -ServerName 'NPS01' -ADGroups 'VPN_Staff'
        $out.FGT | Set-Clipboard
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns CLI text; changes nothing.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string[]]$Usernames,
        [Parameter(Mandatory)][ValidateSet('radius', 'ldap')][string]$TargetType,
        [Parameter(Mandatory)][string]$ServerName,
        [string[]]$ADGroups = @(),
        [string[]]$DisabledUsernames = @(),
        [string]$GroupName,
        [string[]]$ExistingGroupMembers = @(),
        [string]$Vdom
    )

    $disabledSet = [Collections.Generic.HashSet[string]]::new([string[]]@($DisabledUsernames | Where-Object { $_ }), [StringComparer]::OrdinalIgnoreCase)

    $fgtLines = [Collections.Generic.List[string]]::new()
    $fgtLines.Add('config user local')
    foreach ($u in $Usernames) {
        $fgtLines.Add("    edit `"$u`"")
        if ($disabledSet.Contains($u)) { $fgtLines.Add('        set status disable') }
        $fgtLines.Add("        set type $TargetType")
        $fgtLines.Add("        set $TargetType-server `"$ServerName`"")
        $fgtLines.Add('    next')
    }
    $fgtLines.Add('end')
    $fgtText = $fgtLines -join "`r`n"

    if ($GroupName) {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $members = [Collections.Generic.List[string]]::new()
        foreach ($m in @($ExistingGroupMembers) + @($Usernames)) { if ($m -and $seen.Add($m)) { $members.Add($m) } }
        $quoted = (@($members | ForEach-Object { "`"$_`"" }) -join ' ')
        $fgtText += "`r`n`r`nconfig user group`r`n    edit `"$GroupName`"`r`n        set member $quoted`r`n    next`r`nend"
    }
    if ($Vdom) {
        $indented = ($fgtText -split "`r`n" | ForEach-Object { if ($_) { "    $_" } else { $_ } }) -join "`r`n"
        $fgtText = "config vdom`r`n    edit `"$Vdom`"`r`n$indented`r`nend"
    }

    # One Add-ADGroupMember per user: a call with several members fails as a whole when one of
    # them doesn't resolve, adding nobody.
    $quotedMembers = (@($Usernames | ForEach-Object { "`"$_`"" }) -join ', ')
    $quotedGroups = (@($ADGroups | ForEach-Object { "`"$_`"" }) -join ', ')
    $adLines = @(
        "`$Members = @($quotedMembers)"
        "`$ADGroups = @($quotedGroups)"
        ''
        '$Success = @()'
        '$FailedUsers = @()'
        ''
        'foreach ($user in $Members) {'
        '    try {'
        '        foreach ($group in $ADGroups) { Add-ADGroupMember -Identity $group -Members @($user) }'
        '        $Success += $user'
        '    } catch {'
        '        $FailedUsers += $user'
        '    }'
        '}'
        ''
        '$Success.Count'
        '$FailedUsers.Count'
        '$FailedUsers'
    )

    [pscustomobject]@{
        PSTypeName = 'NSP.FortiGate.UserConversion'
        FGT        = $fgtText
        AD         = $adLines -join "`r`n"
    }
}
