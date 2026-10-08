function Split-NSPFortiGateToken {
    <#
    .SYNOPSIS
        Splits one FortiOS CLI line into words, honoring double quotes.
    .DESCRIPTION
        Inside quotes, \" and \\ are unescaped and any other backslash is kept,
        so LDAP DNs such as CN=Doe\, John survive. Unterminated is set when a
        quote is still open at the end of the text (a multi-line value).

        A line whose quotes all close is split by one regex match; only a line
        with an open quote (the first line of a certificate or multi-line
        comment) takes the character-by-character path. Called once per line of
        a backup, so this is the parser's hot path.
    #>
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    if ($Text.IndexOf('"') -lt 0) {
        return [pscustomobject]@{ Tokens = [string[]]$Text.Split([char[]]$null, [StringSplitOptions]::RemoveEmptyEntries); Unterminated = $false }
    }
    $match = $script:NSPFortiGateLinePattern.Match($Text)
    if ($match.Success) {
        $captures = $match.Groups['token'].Captures
        $tokens = [string[]]::new($captures.Count)
        for ($i = 0; $i -lt $captures.Count; $i++) {
            $token = $captures[$i].Value
            if ($token.IndexOf('"') -ge 0) {
                # Unquote each quoted run and unescape \" and \\ inside it; unquoted runs stay as they are.
                # Most are one plain "..." run, so the regex evaluator is only used for escapes.
                if ($token.IndexOf('\') -ge 0) { $token = $script:NSPFortiGateQuotedPattern.Replace($token, $script:NSPFortiGateUnquote) }
                elseif ($token.Length -ge 2 -and $token[0] -eq '"' -and $token.IndexOf('"', 1) -eq $token.Length - 1) { $token = $token.Substring(1, $token.Length - 2) }
                else { $token = $script:NSPFortiGateQuotedPattern.Replace($token, '$1') }
            }
            $tokens[$i] = $token
        }
        return [pscustomobject]@{ Tokens = $tokens; Unterminated = $false }
    }

    # An open quote: walk the characters so the open value's text is kept exactly.
    $list = [System.Collections.Generic.List[string]]::new()
    $current = [System.Text.StringBuilder]::new()
    $inQuote = $false
    $hasToken = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($inQuote) {
            if ($c -eq '\' -and $i + 1 -lt $Text.Length -and ($Text[$i + 1] -eq '"' -or $Text[$i + 1] -eq '\')) {
                $i++
                [void]$current.Append($Text[$i])
            } elseif ($c -eq '"') {
                $inQuote = $false
            } else {
                [void]$current.Append($c)
            }
        } elseif ([char]::IsWhiteSpace($c)) {
            if ($hasToken) {
                $list.Add($current.ToString())
                [void]$current.Clear()
                $hasToken = $false
            }
        } elseif ($c -eq '"') {
            $inQuote = $true
            $hasToken = $true
        } else {
            [void]$current.Append($c)
            $hasToken = $true
        }
    }
    if ($hasToken) { $list.Add($current.ToString()) }
    [pscustomobject]@{ Tokens = [string[]]$list.ToArray(); Unterminated = $inQuote }
}

# Built once at import. A token is a run of unquoted characters and complete quoted strings; the whole
# line must be such tokens separated by whitespace, so any unclosed quote fails the match. Each token is
# atomic, so a failing line (an open quote) is rejected in linear time instead of backtracking.
$script:NSPFortiGateLinePattern = [regex]::new('^\s*(?:(?<token>(?>(?:[^\s"]+|"(?:\\.|[^"\\])*")+))\s*)*$', [Text.RegularExpressions.RegexOptions]::Compiled -bor [Text.RegularExpressions.RegexOptions]::Singleline)
$script:NSPFortiGateQuotedPattern = [regex]::new('"((?:\\.|[^"\\])*)"', [Text.RegularExpressions.RegexOptions]::Compiled -bor [Text.RegularExpressions.RegexOptions]::Singleline)
$script:NSPFortiGateEscapePattern = [regex]::new('\\(["\\])', [Text.RegularExpressions.RegexOptions]::Compiled)
$script:NSPFortiGateUnquote = [Text.RegularExpressions.MatchEvaluator] { param($m) $script:NSPFortiGateEscapePattern.Replace($m.Groups[1].Value, '$1') }
