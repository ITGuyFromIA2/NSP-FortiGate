function Split-NSPFortiGateLineBatch {
    <#
    .SYNOPSIS
        Tokenizes every line at once, for the tree builder: one string[] per line, or $null for a line
        that leaves a quote open.
    .DESCRIPTION
        Same rules as Split-NSPFortiGateToken, which handles the open-quote lines (and the multi-line
        text they start). Kept apart from Read-NSPFortiGateConfigTree on purpose, for speed:
          - one call for the whole file, since calling a function per line costs more than the split
            itself on Windows PowerShell 5.1 (about 0.3 ms a call);
          - its own small loop, which PowerShell 7 runs several times faster than the same code inside
            the tree builder's larger loop.
        Together that took a 20,000-line backup from 12 seconds to under 2.
    #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Text)

    $linePattern = $script:NSPFortiGateLinePattern
    $quotedPattern = $script:NSPFortiGateQuotedPattern
    $unquote = $script:NSPFortiGateUnquote
    $result = [object[]]::new($Text.Count)
    for ($n = 0; $n -lt $Text.Count; $n++) {
        $line = $Text[$n]
        if ($line.IndexOf([char]34) -lt 0) {
            $result[$n] = [string[]]$line.Split([char[]]$null, [StringSplitOptions]::RemoveEmptyEntries)
            continue
        }
        $match = $linePattern.Match($line)
        if (-not $match.Success) { continue }
        $captures = $match.Groups['token'].Captures
        $tokens = [string[]]::new($captures.Count)
        for ($c = 0; $c -lt $captures.Count; $c++) {
            $token = $captures[$c].Value
            if ($token.IndexOf([char]34) -ge 0) {
                # Most quoted tokens are one plain "..." run; the regex evaluator is only for escapes.
                if ($token.IndexOf([char]92) -ge 0) { $token = $quotedPattern.Replace($token, $unquote) }
                elseif ($token.Length -ge 2 -and $token[0] -eq [char]34 -and $token.IndexOf([char]34, 1) -eq $token.Length - 1) { $token = $token.Substring(1, $token.Length - 2) }
                else { $token = $quotedPattern.Replace($token, '$1') }
            }
            $tokens[$c] = $token
        }
        $result[$n] = $tokens
    }
    , $result
}
