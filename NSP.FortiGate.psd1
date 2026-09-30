@{
    RootModule = 'NSP.FortiGate.psm1'
    ModuleVersion = '0.2.0'
    GUID = '70c15a8c-ba07-4d65-986d-54b54c501991'
    Author = 'Network Systems Plus'
    CompanyName = 'Network Systems Plus'
    Copyright = '(c) Network Systems Plus. All rights reserved.'
    Description = 'Parse FortiGate configuration backups and CLI captures into CSV-ready objects, resolve what firewall policies reference, and write a printable VPN access report (HTML + Excel) that ties tunnel rules to NPS policies and AD groups.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'ConvertFrom-NSPFortiGateConfig'
        'ConvertFrom-NSPFortiGateSection'
        'ConvertFrom-NSPFortiGatePolicy'
        'Get-NSPFortiGatePolicyAccess'
        'Export-NSPFortiGateCsv'
        'Export-NSPFortiGateVpnReport'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('FortiGate', 'FortiOS', 'Firewall', 'VPN', 'IPsec', 'NPS', 'RADIUS', 'Documentation', 'Report', 'Excel', 'Windows')
            ProjectUri = 'https://github.com/ITGuyFromIA2/NSP-FortiGate'
            LicenseUri = 'https://github.com/ITGuyFromIA2/NSP-FortiGate/blob/main/LICENSE'
            ReleaseNotes = 'VPN report: NPS server block on the cover (-NpsFacts, RADIUS clients from ias.xml) and a Check for RADIUS source addresses that are not NPS RADIUS clients (-RadiusSourceIp, source-ip). See CHANGELOG.md.'
        }
    }
}
