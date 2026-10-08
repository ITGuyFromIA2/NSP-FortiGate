function Write-NSPFortiGateXlsx {
    <#
    .SYNOPSIS
        Writes a minimal .xlsx workbook: one worksheet per table, no Excel needed.
    .DESCRIPTION
        Each sheet is @{ Name; Columns; Rows } where Rows are hashtables keyed by
        column name. The header row is bold, frozen, and has an AutoFilter;
        cells wrap and align to the top; column widths follow content (capped).
        Whole numbers are written as numbers, everything else as text.
        Built with System.IO.Compression (in .NET 4.5+), so it works on a bare
        Windows PowerShell 5.1 host.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Sheet
    )

    Add-Type -AssemblyName System.IO.Compression
    $escape = {
        param([string]$Text)
        # XML 1.0 forbids most control characters; drop them rather than fail the file.
        [Security.SecurityElement]::Escape(($Text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''))
    }
    $columnName = {
        param([int]$Index)
        $name = ''
        $n = $Index + 1
        while ($n -gt 0) { $n--; $name = [char](65 + ($n % 26)) + $name; $n = [math]::Floor($n / 26) }
        $name
    }

    $used = @{}
    $names = foreach ($item in $Sheet) {
        $name = ($item.Name -replace '[\[\]:*?/\\]', '-').Trim()
        if ($name.Length -gt 31) { $name = $name.Substring(0, 31) }
        $base = $name
        $suffix = 2
        while ($used.ContainsKey($name.ToLowerInvariant())) { $name = '{0} {1}' -f $base.Substring(0, [math]::Min($base.Length, 28)), $suffix++ }
        $used[$name.ToLowerInvariant()] = $true
        $name
    }
    $names = @($names)

    $parts = [ordered]@{}
    $parts['[Content_Types].xml'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
        (@(for ($i = 1; $i -le $names.Count; $i++) { "<Override PartName=""/xl/worksheets/sheet$i.xml"" ContentType=""application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml""/>" }) -join '') + '</Types>'
    $parts['_rels/.rels'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    $parts['xl/workbook.xml'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' +
        (@(for ($i = 0; $i -lt $names.Count; $i++) { "<sheet name=""$(& $escape $names[$i])"" sheetId=""$($i + 1)"" r:id=""rId$($i + 1)""/>" }) -join '') + '</sheets></workbook>'
    $parts['xl/_rels/workbook.xml.rels'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        (@(for ($i = 1; $i -le $names.Count; $i++) { "<Relationship Id=""rId$i"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"" Target=""worksheets/sheet$i.xml""/>" }) -join '') +
        "<Relationship Id=""rId$($names.Count + 1)"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"" Target=""styles.xml""/></Relationships>"
    # Style 0: default. 1: bold header on grey. 2: wrapped, top-aligned body.
    $parts['xl/styles.xml'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="10"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE8E8E8"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'

    for ($s = 0; $s -lt $Sheet.Count; $s++) {
        $columns = @($Sheet[$s].Columns)
        $rows = @($Sheet[$s].Rows)
        $widths = @(foreach ($column in $columns) { [math]::Max(8, $column.Length + 2) })
        $xml = [System.Text.StringBuilder]::new()
        $cells = [System.Text.StringBuilder]::new()
        [void]$cells.Append('<row r="1">')
        for ($c = 0; $c -lt $columns.Count; $c++) {
            [void]$cells.Append("<c r=""$(& $columnName $c)1"" t=""inlineStr"" s=""1""><is><t xml:space=""preserve"">$(& $escape $columns[$c])</t></is></c>")
        }
        [void]$cells.Append('</row>')
        for ($r = 0; $r -lt $rows.Count; $r++) {
            $rowNumber = $r + 2
            [void]$cells.Append("<row r=""$rowNumber"">")
            for ($c = 0; $c -lt $columns.Count; $c++) {
                $value = [string]$rows[$r][$columns[$c]]
                if ($value -eq '') { continue }
                $ref = "$(& $columnName $c)$rowNumber"
                $longest = ($value -split "`n" | Measure-Object -Property Length -Maximum).Maximum
                if ($longest + 2 -gt $widths[$c]) { $widths[$c] = [math]::Min(60, $longest + 2) }
                if ($value -match '^-?\d{1,15}$') {
                    [void]$cells.Append("<c r=""$ref"" s=""2""><v>$value</v></c>")
                } else {
                    [void]$cells.Append("<c r=""$ref"" t=""inlineStr"" s=""2""><is><t xml:space=""preserve"">$(& $escape $value)</t></is></c>")
                }
            }
            [void]$cells.Append('</row>')
        }
        $lastColumn = & $columnName ([math]::Max(0, $columns.Count - 1))
        [void]$xml.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
        [void]$xml.Append('<sheetViews><sheetView workbookViewId="0"' + $(if ($s -eq 0) { ' tabSelected="1"' } else { '' }) + '><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
        [void]$xml.Append('<cols>')
        for ($c = 0; $c -lt $columns.Count; $c++) { [void]$xml.Append("<col min=""$($c + 1)"" max=""$($c + 1)"" width=""$($widths[$c])"" customWidth=""1""/>") }
        [void]$xml.Append('</cols><sheetData>').Append($cells.ToString()).Append('</sheetData>')
        if ($rows.Count) { [void]$xml.Append("<autoFilter ref=""A1:$lastColumn$($rows.Count + 1)""/>") }
        [void]$xml.Append('</worksheet>')
        $parts["xl/worksheets/sheet$($s + 1).xml"] = $xml.ToString()
    }

    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $utf8 = [System.Text.UTF8Encoding]::new($false)
            foreach ($name in $parts.Keys) {
                $writer = [System.IO.StreamWriter]::new($zip.CreateEntry($name).Open(), $utf8)
                try { $writer.Write($parts[$name]) } finally { $writer.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
    Get-Item -LiteralPath $Path
}
