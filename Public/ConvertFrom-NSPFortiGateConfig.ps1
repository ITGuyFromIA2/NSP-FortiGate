function ConvertFrom-NSPFortiGateConfig {
    <#
    .SYNOPSIS
        Parses FortiOS 'show' output into its config/edit/set tree.
    .DESCRIPTION
        Accepts console captures as-is: prompt lines, pager prompts, grep -f
        "<---" markers, and terminal line wraps are handled. Returns the root
        sections; each has Path, Vdom, Settings, Entries, and nested Sections.
        Each entry has Name, Settings (setting name to string array), and
        nested Sections. Use this to explore a capture or to reach settings
        the CSV commands do not surface.
    .PARAMETER Path
        One or more capture files. Their sections are returned together.
    .PARAMETER InputObject
        CLI text from the pipeline, for example Get-Clipboard.
    .EXAMPLE
        ConvertFrom-NSPFortiGateConfig -Path .\policies.txt | Select-Object Path, @{ n = 'Entries'; e = { $_.Entries.Count } }
    .EXAMPLE
        Get-Clipboard | ConvertFrom-NSPFortiGateConfig
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][ValidateNotNullOrEmpty()][string[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Text')][AllowEmptyString()][string[]]$InputObject
    )

    begin { $buffer = [System.Collections.Generic.List[string]]::new() }
    process {
        foreach ($text in $InputObject) { $buffer.AddRange([string[]]($text -split '\r?\n')) }
    }
    end {
        Read-NSPFortiGateInput -Path $Path -Line $buffer.ToArray() | ForEach-Object { $_ }
    }
}
