function Split-NSPFortiGateToken {
    <#
    .SYNOPSIS
        Splits one FortiOS CLI line into words, honoring double quotes.
    .DESCRIPTION
        Inside quotes, \" and \\ are unescaped and any other backslash is kept,
        so LDAP DNs such as CN=Doe\, John survive. Unterminated is set when a
        quote is still open at the end of the text (a multi-line value).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $tokens = New-Object System.Collections.Generic.List[string]
    $current = New-Object System.Text.StringBuilder
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
                $tokens.Add($current.ToString())
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
    if ($hasToken) { $tokens.Add($current.ToString()) }

    [pscustomobject]@{
        Tokens = [string[]]$tokens.ToArray()
        Unterminated = $inQuote
    }
}
