function Format-NSPFortiGateHtmlTable {
    <#
    .SYNOPSIS
        Renders rows as an HTML table, merging repeated group cells.
    .DESCRIPTION
        Rows are hashtables keyed by column name; a '_class' key sets the row
        class. -SpanColumns merge repeated cells (rowspan), nested in the order
        given: a cell merges while its value and every earlier span column's
        repeat, so a group's name and "used by" print once beside its members. Values are
        HTML-encoded; line breaks become <br>. -NoWrapColumns keep short values
        (IDs, status) on one line while long names wrap.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string[]]$Columns,
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [string[]]$SpanColumns = @(),
        [string[]]$NoWrapColumns = @(),
        [hashtable]$ColumnWidth = @{},
        [string]$Empty = 'None referenced.'
    )

    if ($Rows.Count -eq 0) { return "<p class=""empty"">$([System.Net.WebUtility]::HtmlEncode($Empty))</p>" }
    $encode = { param($Value) [System.Net.WebUtility]::HtmlEncode([string]$Value) -replace '\r?\n', '<br>' }
    # Cells: offer line breaks after _ - . / so long object names (VPN_Branch_Servers_All)
    # wrap at their natural joints instead of mid-word, and columns size to those pieces.
    $encodeCell = { param($Value) ([System.Net.WebUtility]::HtmlEncode([string]$Value) -replace '([_./-])', '$1<wbr>') -replace '\r?\n', '<br>' }

    $html = New-Object System.Text.StringBuilder
    [void]$html.Append('<table><thead><tr>')
    foreach ($column in $Columns) {
        $nowrap = if ($NoWrapColumns -contains $column) { ' class="nw"' } else { '' }
        # A width hint keeps one long-text column from squeezing the rest under automatic table layout.
        $width = if ($ColumnWidth.ContainsKey($column)) { " style=""width: $($ColumnWidth[$column])""" } else { '' }
        [void]$html.Append("<th$nowrap$width>$(& $encode $column)</th>")
    }
    [void]$html.Append('</tr></thead><tbody>')

    # Span columns nest in the order given: a cell merges while its own value and those of the span
    # columns before it repeat, so a policy spans its VSAs and each VSA spans its firewall rules.
    $spanKey = @(for ($i = 0; $i -lt $Rows.Count; $i++) {
        $parts = @(foreach ($column in $SpanColumns) { [string]$Rows[$i][$column] })
        , @(for ($level = 0; $level -lt $parts.Count; $level++) { $parts[0..$level] -join "`t" })
    })
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $row = $Rows[$i]
        $startsGroup = $SpanColumns.Count -eq 0 -or $i -eq 0 -or $spanKey[$i - 1][0] -ne $spanKey[$i][0]
        $class = if ($row['_class']) { " class=""$($row['_class'])""" } elseif ($startsGroup -and $i -gt 0 -and $SpanColumns.Count) { ' class="group-start"' } else { '' }
        [void]$html.Append("<tr$class>")
        foreach ($column in $Columns) {
            $level = if ($SpanColumns.Count) { [array]::IndexOf($SpanColumns, $column) } else { -1 }
            if ($level -ge 0) {
                if ($i -gt 0 -and $spanKey[$i - 1][$level] -eq $spanKey[$i][$level]) { continue }
                $span = 1
                while ($i + $span -lt $Rows.Count -and $spanKey[$i + $span][$level] -eq $spanKey[$i][$level]) { $span++ }
                $rowspan = if ($span -gt 1) { " rowspan=""$span""" } else { '' }
                # A merged cell sits in its first row; 'mixed' keeps it from taking that row's styling
                # (such as a disabled rule) when the rows it spans differ.
                $mixed = if (@($Rows[$i..($i + $span - 1)] | ForEach-Object { [string]$_['_class'] } | Select-Object -Unique).Count -gt 1) { ' mixed' } else { '' }
                if ($NoWrapColumns -contains $column) { [void]$html.Append("<td class=""group nw$mixed""$rowspan>$(& $encode $row[$column])</td>") }
                else { [void]$html.Append("<td class=""group$mixed""$rowspan>$(& $encodeCell $row[$column])</td>") }
            } else {
                # Browsers still break at <wbr> inside white-space: nowrap, so no-wrap cells get none.
                if ($NoWrapColumns -contains $column) { [void]$html.Append("<td class=""nw"">$(& $encode $row[$column])</td>") }
                else { [void]$html.Append("<td>$(& $encodeCell $row[$column])</td>") }
            }
        }
        [void]$html.Append('</tr>')
    }
    [void]$html.Append('</tbody></table>')
    $html.ToString()
}
