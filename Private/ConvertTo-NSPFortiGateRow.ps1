function ConvertTo-NSPFortiGateRow {
    <#
    .SYNOPSIS
        Flattens every instance of one config section into uniform CSV rows.
    .DESCRIPTION
        All rows share one property set (schema columns, then every other
        setting seen in any entry, then nested blocks), because Export-Csv
        takes its header from the first object only. -Include limits output
        to entries whose object key (see Get-NSPFortiGateObjectKey) is listed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Section,
        [string]$Delimiter = '; ',
        [switch]$IncludeSecrets,
        [switch]$NoDefaults,
        [System.Collections.Generic.HashSet[string]]$Include
    )

    $path = $Section[0].Path
    $schemas = Get-NSPFortiGateSchema
    $schema = if ($schemas.Contains($path)) { $schemas[$path] } else { @{ IdColumn = 'Id'; Columns = [ordered]@{}; Defaults = @{} } }
    $childColumns = if ($schema.ChildColumns) { $schema.ChildColumns } else { [ordered]@{} }

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($instance in $Section) {
        $sequence = 0
        foreach ($entry in $instance.Entries) {
            $sequence++
            if ($null -ne $Include -and -not $Include.Contains((Get-NSPFortiGateObjectKey -Vdom $entry.Vdom -Path $path -Name $entry.Name))) { continue }
            $records.Add(@{ Vdom = $entry.Vdom; Sequence = $sequence; Id = $entry.Name; Settings = $entry.Settings; Sections = $entry.Sections })
        }
        # Sections such as 'system global' hold settings directly instead of edit entries.
        if ($instance.Entries.Count -eq 0 -and $instance.Settings.Count -and $null -eq $Include) {
            $records.Add(@{ Vdom = $instance.Vdom; Sequence = 1; Id = ''; Settings = $instance.Settings; Sections = $instance.Sections })
        }
    }
    if ($records.Count -eq 0) { return }

    $knownKeys = @($schema.Columns.Values | Where-Object { $null -ne $_ })
    $knownChildren = @($childColumns.Values | ForEach-Object { $_.Section })
    $reserved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('Vdom', 'Sequence', $schema.IdColumn) + @($schema.Columns.Keys) + @($childColumns.Keys)) { [void]$reserved.Add($name) }

    $extraKeys = [System.Collections.Generic.List[string]]::new()
    $seenKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $childPaths = [System.Collections.Generic.List[string]]::new()
    $seenChildren = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $records) {
        foreach ($key in $record.Settings.Keys) {
            if ($knownKeys -notcontains $key -and $seenKeys.Add($key)) { $extraKeys.Add($key) }
        }
        foreach ($child in $record.Sections) {
            if ($knownChildren -notcontains $child.Path -and $seenChildren.Add($child.Path)) { $childPaths.Add($child.Path) }
        }
    }
    $showVdom = @($records | Where-Object { $_.Vdom }).Count -gt 0

    foreach ($record in $records) {
        $row = [ordered]@{}
        if ($showVdom) { $row['Vdom'] = $record.Vdom }
        $row['Sequence'] = $record.Sequence
        $row[$schema.IdColumn] = $record.Id
        foreach ($column in $schema.Columns.Keys) {
            $key = $schema.Columns[$column]
            $row[$column] = if ($null -eq $key) {
                Get-NSPFortiGateObjectSummary -Path $path -Settings $record.Settings
            } elseif ($record.Settings.Contains($key)) {
                Format-NSPFortiGateValue -Key $key -Value $record.Settings[$key] -Delimiter $Delimiter -IncludeSecrets:$IncludeSecrets
            } elseif (-not $NoDefaults -and $schema.Defaults.Contains($key)) {
                $schema.Defaults[$key]
            } else { '' }
        }
        foreach ($column in $childColumns.Keys) {
            $spec = $childColumns[$column]
            $row[$column] = Format-NSPFortiGateChild -Section @($record.Sections | Where-Object Path -eq $spec.Section) -Keys $spec.Keys -Separator $spec.Separator -Delimiter $Delimiter -IncludeSecrets:$IncludeSecrets
        }
        foreach ($key in $extraKeys) {
            $column = if ($reserved.Contains($key)) { "$key (set)" } else { $key }
            $row[$column] = if ($record.Settings.Contains($key)) {
                Format-NSPFortiGateValue -Key $key -Value $record.Settings[$key] -Delimiter $Delimiter -IncludeSecrets:$IncludeSecrets
            } else { '' }
        }
        foreach ($childPath in $childPaths) {
            $row["config $childPath"] = Format-NSPFortiGateChild -Section @($record.Sections | Where-Object Path -eq $childPath) -Delimiter $Delimiter -IncludeSecrets:$IncludeSecrets
        }
        [pscustomobject]$row
    }
}
