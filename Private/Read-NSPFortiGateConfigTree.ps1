function Read-NSPFortiGateConfigTree {
    <#
    .SYNOPSIS
        Builds the config/edit/set tree from FortiOS CLI output lines.
    .DESCRIPTION
        Returns the root sections. Each section has Path, Vdom, LineNumber,
        Settings, Entries, and Sections; each entry has Name, Vdom, LineNumber,
        Settings, and Sections. Settings values are string arrays.

        Console noise is tolerated: terminal wraps are rejoined and grep
        markers removed (Join-NSPFortiGateWrappedLine), prompt lines outside a
        block are skipped, and a quoted value spanning lines (a certificate,
        a multi-line comment) keeps its line breaks.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $roots = [System.Collections.Generic.List[object]]::new()
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $keywords = [System.Collections.Generic.HashSet[string]]::new([string[]]@('config', 'edit', 'set', 'unset', 'append', 'select', 'unselect', 'next', 'end'))
    $pending = $null
    $startLine = 0
    # Write-Verbose is a cmdlet call even when verbose output is off; skip it unless asked for.
    $verbose = $VerbosePreference -ne 'SilentlyContinue'
    $logicalLines = @(Join-NSPFortiGateWrappedLine -Line $Line)
    # Every complete line tokenized up front, in one call ($null where a quote is left open); see
    # Split-NSPFortiGateLineBatch for why this isn't done line by line here.
    $texts = [string[]]::new($logicalLines.Count)
    for ($n = 0; $n -lt $logicalLines.Count; $n++) { $texts[$n] = $logicalLines[$n].Text }
    $prepared = Split-NSPFortiGateLineBatch -Text $texts

    for ($n = 0; $n -le $logicalLines.Count; $n++) {
        $logical = if ($n -lt $logicalLines.Count) { $logicalLines[$n] } else { $null }
        if ($null -ne $logical) {
            if ($null -ne $pending) {
                # Inside a multi-line quoted value (a certificate): only check whether this line closes it.
                # Re-walking the whole value on every line made long certificates quadratic.
                $text = $pending + "`n" + $logical.Text
                $closed = (Split-NSPFortiGateLineBatch -Text $text)[0]
                if ($null -eq $closed) { $pending = $text; continue }
                $parsed = @{ Tokens = $closed; Unterminated = $false }
            } else {
                $text = $logical.Text
                $startLine = $logical.LineNumber
                if ($null -ne $prepared[$n]) {
                    $parsed = @{ Tokens = $prepared[$n]; Unterminated = $false }
                } elseif ($text -match '^\s*(set|append)\s') {
                    # Only a set/append line may open a multi-line quoted value; a stray quote in a prompt must not swallow the file.
                    $pending = $text
                    continue
                } else {
                    $parsed = Split-NSPFortiGateToken -Text $text
                }
            }
        } elseif ($null -ne $pending) {
            Write-Warning "Unterminated quoted value starting at line $startLine."
            $parsed = Split-NSPFortiGateToken -Text $pending
        } else {
            break
        }
        $pending = $null

        $tokens = $parsed.Tokens
        if ($tokens.Count -eq 0) { continue }
        $command = $tokens[0].ToLowerInvariant()
        $top = if ($stack.Count) { $stack.Peek() } else { $null }

        if (-not $keywords.Contains($command)) {
            if ($verbose -and $null -ne $top) { Write-Verbose "Skipped unrecognized line $startLine`: $($tokens -join ' ')" }
            continue
        }

        switch ($command) {
            'config' {
                if ($tokens.Count -lt 2) { if ($verbose) { Write-Verbose "Skipped 'config' without a path at line $startLine." }; break }
                $path = ($tokens[1..($tokens.Count - 1)] -join ' ')
                $vdom = ''
                if ($null -ne $top) {
                    $vdom = $top.Node.Vdom
                    if ($top.Kind -eq 'Entry' -and $top.SectionPath -eq 'vdom') { $vdom = $top.Node.Name }
                    elseif ($top.Kind -eq 'Section' -and $top.Node.Path -eq 'global') { $vdom = 'global' }
                }
                $section = [pscustomobject]@{
                    PSTypeName = 'NSP.FortiGate.ConfigSection'
                    Path = $path
                    Vdom = $vdom
                    LineNumber = $startLine
                    Settings = [ordered]@{}
                    Entries = [System.Collections.Generic.List[object]]::new()
                    Sections = [System.Collections.Generic.List[object]]::new()
                }
                if ($null -eq $top) { $roots.Add($section) } else { $top.Node.Sections.Add($section) }
                $stack.Push(@{ Kind = 'Section'; Node = $section })
            }
            'edit' {
                if ($null -eq $top -or $top.Kind -ne 'Section') { if ($verbose) { Write-Verbose "Skipped 'edit' outside a config block at line $startLine." }; break }
                $entry = [pscustomobject]@{
                    PSTypeName = 'NSP.FortiGate.ConfigEntry'
                    Name = if ($tokens.Count -gt 1) { $tokens[1] } else { '' }
                    Vdom = $top.Node.Vdom
                    LineNumber = $startLine
                    Settings = [ordered]@{}
                    Sections = [System.Collections.Generic.List[object]]::new()
                }
                $top.Node.Entries.Add($entry)
                $stack.Push(@{ Kind = 'Entry'; Node = $entry; SectionPath = $top.Node.Path })
            }
            'next' {
                if ($null -ne $top -and $top.Kind -eq 'Entry') { [void]$stack.Pop() }
            }
            'end' {
                if ($null -ne $top -and $top.Kind -eq 'Entry') { [void]$stack.Pop() }
                if ($stack.Count -and $stack.Peek().Kind -eq 'Section') { [void]$stack.Pop() }
            }
            default {
                if ($null -eq $top -or $tokens.Count -lt 2) { break }
                $settings = $top.Node.Settings
                $key = $tokens[1]
                $values = if ($tokens.Count -gt 2) { $tokens[2..($tokens.Count - 1)] } else { @() }
                # Only append/unselect need the current value.
                $existing = if ($command -in 'append', 'unselect' -and $settings.Contains($key)) { @($settings[$key]) } else { @() }
                switch ($command) {
                    'unset' { $settings[$key] = [string[]]@() }
                    'append' { $settings[$key] = [string[]]($existing + $values) }
                    'unselect' { $settings[$key] = [string[]]@($existing | Where-Object { $values -notcontains $_ }) }
                    default { $settings[$key] = [string[]]$values }
                }
            }
        }
    }

    if ($stack.Count) { Write-Warning 'Input ended inside a config block without a matching end; output may be incomplete.' }
    , $roots.ToArray()
}
