function Export-NSPFortiGateVpnReport {
    <#
    .SYNOPSIS
        Writes a printable HTML document and an Excel workbook of a VPN tunnel's access chain.
    .DESCRIPTION
        One sheet per topic; in the HTML each starts on a new printed page (landscape) so the
        printout can be separated and cross-referenced, and in the workbook each is its own tab
        (header row frozen and filterable) after an About tab:

          Cover  tunnel settings, sources, checks worth a look, contents
          1      firewall policies using the tunnel
          2      user groups, the VSA each expects, and the NPS policy that sends it
          3      service groups expanded to protocol/port
          4      address groups expanded to addresses
          5      certificate peer groups, the subject each peer matches, and its template
          6      NPS network policies: conditions, VSAs returned, where each lands
          7      AD group membership tree
          8      certificate templates: enrollment groups and TameMyCerts OU stamp
          9      effective access by AD group, including users an earlier NPS policy shadows

        Sheets 1-5 need only the FortiGate captures. Sheets 6 and 9 need -NpsConfig, sheets 7 and 8
        need -AdInventory; without them those sheets print as headed placeholders. The Checks list
        on the cover collects mismatches found along the way (VSA case differences, VSAs no
        FortiGate group matches, shadowed users, peers no template stamps).
    .PARAMETER Path
        FortiGate capture files, parsed together (policies, groups, services, addresses, RADIUS,
        peers, IPsec phase1/phase2), or a full configuration backup.
    .PARAMETER Tunnel
        Phase1 interface name. Only policies with it as source or destination interface are
        documented. Omit to document every policy loaded.
    .PARAMETER OutputPath
        The .html file to write.
    .PARAMETER ExcelPath
        The .xlsx file to write. Defaults to OutputPath with an .xlsx extension.
    .PARAMETER NoExcel
        Write the HTML only.
    .PARAMETER NpsConfig
        A copy of the NPS server's ias.xml (C:\Windows\System32\ias\ias.xml) or a 'netsh nps export'.
        Only policies and profiles are read; RADIUS client entries (shared secrets) are not.
    .PARAMETER AdInventory
        The ADInventory_*.json written by AD-Manager menu 6.
    .PARAMETER DeviceName
        Defaults to the hostname in the capture's CLI prompt.
    .EXAMPLE
        Export-NSPFortiGateVpnReport -Path .\captures\*.txt -Tunnel 'Dialup-IKEv2' -OutputPath .\Dialup-IKEv2.html
    .EXAMPLE
        Export-NSPFortiGateVpnReport -Path .\captures\*.txt -Tunnel 'Dialup-IKEv2' -NpsConfig .\ias.xml -AdInventory .\ADInventory_example.json -OutputPath .\Dialup-IKEv2.html
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, Position = 0)][ValidateNotNullOrEmpty()][string[]]$Path,
        [string]$Tunnel,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [string]$ExcelPath,
        [switch]$NoExcel,
        [string]$NpsConfig,
        [string]$AdInventory,
        [string]$DeviceName,
        [string]$Title
    )

    $report = Get-NSPFortiGateVpnReportData -Path $Path -Tunnel $Tunnel -NpsConfig $NpsConfig -AdInventory $AdInventory -DeviceName $DeviceName -Title $Title
    $encode = { param($Value) [System.Net.WebUtility]::HtmlEncode([string]$Value) }
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm'

    $css = @'
@page { size: letter landscape; margin: 0.45in; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", Calibri, Arial, sans-serif; font-size: 10pt; color: #1a1a1a; margin: 0 auto; max-width: 1700px; padding: 16px; background: #fff; }
h1 { font-size: 20pt; margin: 0 0 4px; }
h2 { font-size: 14pt; margin: 0 0 6px; }
.sheet { break-before: page; page-break-before: always; }
.sheet-head { display: flex; justify-content: space-between; border-bottom: 2px solid #1a1a1a; padding-bottom: 4px; margin-bottom: 10px; font-size: 9pt; color: #444; }
.sheet-head strong { color: #1a1a1a; }
p { margin: 0 0 8px; }
ul { margin: 0 0 10px; padding-left: 20px; }
table { width: 100%; border-collapse: collapse; font-size: 9pt; }
thead { display: table-header-group; }
tr { break-inside: avoid; page-break-inside: avoid; }
th { background: #e8e8e8; text-align: left; }
th, td { border: 1px solid #9a9a9a; padding: 3px 6px; vertical-align: top; overflow-wrap: break-word; }
td.group { font-weight: 600; background: #f6f6f6; }
th.nw, td.nw { white-space: nowrap; overflow-wrap: normal; }
tr.disabled td { color: #777; font-style: italic; }
tr.disabled td.mixed { color: inherit; font-style: normal; }
.empty, .todo { border: 1px dashed #9a9a9a; padding: 18px; color: #555; }
.todo { min-height: 4in; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 3px 16px; margin: 12px 0; }
dt { font-weight: 600; }
dd { margin: 0; }
.checks li { margin: 3px 0; }
.contents li { margin: 2px 0; }
.meta { color: #555; font-size: 9pt; }
@media screen { .sheet { margin-top: 36px; border-top: 1px dashed #bbb; padding-top: 16px; } }
@media print { body { max-width: none; padding: 0; } }
'@

    $html = New-Object System.Text.StringBuilder
    [void]$html.Append("<!DOCTYPE html>`n<html lang=""en""><head><meta charset=""utf-8""><title>$(& $encode $report.Title)</title><style>$css</style></head><body>")
    [void]$html.Append("<section><h1>$(& $encode $report.Title)</h1><p class=""meta"">Generated $generated.</p>")
    if ($report.Facts.Count) {
        [void]$html.Append('<dl>')
        foreach ($key in $report.Facts.Keys) { if ($report.Facts[$key]) { [void]$html.Append("<dt>$(& $encode $key)</dt><dd>$(& $encode $report.Facts[$key])</dd>") } }
        [void]$html.Append('</dl>')
    }
    [void]$html.Append("<p><strong>$($report.PolicyCount)</strong> firewall policies reference this tunnel.</p>")
    if ($report.Checks.Count) {
        [void]$html.Append('<h2>Checks</h2><ul class="checks">')
        foreach ($check in $report.Checks) { [void]$html.Append("<li>$(& $encode $check)</li>") }
        [void]$html.Append('</ul>')
    }
    [void]$html.Append('<h2>Contents</h2><ol class="contents">')
    foreach ($sheet in $report.Sheets) { [void]$html.Append("<li>$(& $encode $sheet.Title)</li>") }
    [void]$html.Append('</ol><p class="meta">Sources:<br>' + (($report.Sources | ForEach-Object { & $encode $_ }) -join '<br>') + '</p></section>')

    for ($i = 0; $i -lt $report.Sheets.Count; $i++) {
        $sheet = $report.Sheets[$i]
        [void]$html.Append("<section class=""sheet""><div class=""sheet-head""><span><strong>Sheet $($i + 1) of $($report.Sheets.Count): $(& $encode $sheet.Title)</strong></span><span>$(& $encode "$($report.DeviceName) / $($report.TunnelName)")</span></div>")
        [void]$html.Append("<h2>$($i + 1). $(& $encode $sheet.Title)</h2><p>$(& $encode $sheet.Intro)</p>")
        if (@($sheet.Notes).Count) {
            [void]$html.Append('<ul>')
            foreach ($note in $sheet.Notes) { [void]$html.Append("<li>$(& $encode $note)</li>") }
            [void]$html.Append('</ul>')
        }
        if ($sheet.Placeholder) {
            [void]$html.Append("<div class=""todo"">$(& $encode $sheet.Placeholder)</div>")
        } else {
            $empty = if ($sheet.Empty) { $sheet.Empty } else { 'None referenced.' }
            $span = if ($sheet.SpanColumns) { $sheet.SpanColumns } else { @() }
            $nowrap = if ($sheet.NoWrapColumns) { $sheet.NoWrapColumns } else { @() }
            $widths = if ($sheet.ColumnWidth) { $sheet.ColumnWidth } else { @{} }
            [void]$html.Append((Format-NSPFortiGateHtmlTable -Columns $sheet.Columns -Rows @($sheet.Rows) -SpanColumns $span -NoWrapColumns $nowrap -ColumnWidth $widths -Empty $empty))
        }
        [void]$html.Append('</section>')
    }
    [void]$html.Append('</body></html>')

    $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $directory = Split-Path -Parent $OutputPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    [IO.File]::WriteAllText($OutputPath, $html.ToString(), (New-Object System.Text.UTF8Encoding $true))
    Get-Item -LiteralPath $OutputPath

    if (-not $NoExcel) {
        if (-not $ExcelPath) { $ExcelPath = [IO.Path]::ChangeExtension($OutputPath, '.xlsx') }
        # About tab: what the HTML cover and sheet introductions say, as rows.
        $about = New-Object System.Collections.Generic.List[hashtable]
        $about.Add(@{ Item = 'Title'; Detail = $report.Title })
        $about.Add(@{ Item = 'Generated'; Detail = $generated })
        foreach ($key in $report.Facts.Keys) { if ($report.Facts[$key]) { $about.Add(@{ Item = $key; Detail = $report.Facts[$key] }) } }
        foreach ($source in $report.Sources) { $about.Add(@{ Item = 'Source'; Detail = $source }) }
        foreach ($check in $report.Checks) { $about.Add(@{ Item = 'Check'; Detail = $check }) }
        for ($i = 0; $i -lt $report.Sheets.Count; $i++) {
            $sheet = $report.Sheets[$i]
            $about.Add(@{ Item = "Sheet $($i + 1): $($sheet.Title)"; Detail = (@($sheet.Intro) + @($sheet.Notes | ForEach-Object { "- $_" }) + @($sheet.Placeholder | Where-Object { $_ })) -join "`n" })
        }
        $workbook = @(@{ Name = 'About'; Columns = @('Item', 'Detail'); Rows = $about.ToArray() })
        for ($i = 0; $i -lt $report.Sheets.Count; $i++) {
            $sheet = $report.Sheets[$i]
            $workbook += @{ Name = "$($i + 1) $($sheet.Title)"; Columns = $sheet.Columns; Rows = @($sheet.Rows) }
        }
        Write-NSPFortiGateXlsx -Path $ExcelPath -Sheet $workbook
    }
}
