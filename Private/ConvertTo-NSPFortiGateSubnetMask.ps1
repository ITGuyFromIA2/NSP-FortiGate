function ConvertTo-NSPFortiGateSubnetMask {
    # Prefix length to dotted mask, e.g. 24 -> 255.255.255.0.
    param([ValidateRange(0, 32)][int]$PrefixLength)
    $bits = if ($PrefixLength -eq 0) { [uint32]0 } else { [uint32]([uint64]4294967295 -shl (32 - $PrefixLength) -band 4294967295) }
    (3, 2, 1, 0 | ForEach-Object { ($bits -shr (8 * $_)) -band 255 }) -join '.'
}
