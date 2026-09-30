function Join-NSPFortiGateWrappedLine {
    <#
    .SYNOPSIS
        Rejoins CLI lines the terminal hard-wrapped, and cleans console noise.
    .DESCRIPTION
        Console captures (PuTTY, the FortiGate web CLI) break long lines at the
        terminal width, even mid-word, mid-quote, or on a space. The width is
        taken as the longest line in the capture: a line exactly that long,
        inside an indented config line, is continued by the next line (with
        nothing between them) unless that line is blank, a CLI command line,
        or a prompt.

        Pager prompts and backspaces are removed before measuring, and grep -f
        "<---" markers are stripped after joining (grep marks the logical line,
        then the terminal wraps it). Returns objects with Text and LineNumber
        (the first physical line of each logical line).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $physical = @(foreach ($raw in $Line) { ($raw -replace '[\x08\r]', '') -replace '--More--', '' })
    $width = 0
    foreach ($text in $physical) { if ($text.Length -gt $width) { $width = $text.Length } }
    # Short captures cannot have wrapped; this also keeps tiny inputs from matching by accident.
    # A configuration backup file (first line '#config-version=...') was never through a terminal:
    # joining there could only damage it, e.g. glue a certificate line onto the one before it.
    $firstLine = @($physical | Where-Object { $_.Trim() } | Select-Object -First 1)
    $isBackup = $firstLine.Count -and $firstLine[0] -match '^#config-version='
    $canWrap = $width -ge 80 -and -not $isBackup
    # A wrap can land on a space, so a continuation may start with one; only a CLI line or prompt ends the run.
    $boundary = '^\s*(config|edit|set|unset|append|select|unselect|next|end)(\s|$)|^\S+( \([^)]*\))? [#$]'

    $i = 0
    while ($i -lt $physical.Count) {
        $text = $physical[$i]
        $lineNumber = $i + 1
        $last = $text
        $i++
        if ($canWrap -and $text -match '^\s') {
            while ($last.Length -eq $width -and $i -lt $physical.Count -and $physical[$i].Length -and $physical[$i] -notmatch $boundary) {
                $last = $physical[$i]
                $text += $last
                $i++
            }
        }
        [pscustomobject]@{ Text = ($text -replace '\s+<---\s*$', ''); LineNumber = $lineNumber }
    }
}
