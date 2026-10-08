function ConvertTo-NSPFortiGateCliName {
    # A name as a quoted CLI token. Embedded double quotes are dropped: FortiOS names can't hold them
    # and a stray one would end the token early.
    param([AllowEmptyString()][string]$Name)
    '"' + $Name.Replace('"', '') + '"'
}
