function Check-DirectoryServicesRestoreMode {
    # Supports Retargeting
    Write-Message "Checking DirectoryServicesRestoreMode"
    $path = "$regtarget_hklm`System\CurrentControlSet\Control\Lsa"
    $path = "Registry::"+$path

    Get-TrawlerItemPropertyProperties -LiteralPath $path | ForEach-Object {
        if ($_.Name -eq 'DsrmAdminLogonBehavior' -and $_.Value -eq 2) {
            $detection = [PSCustomObject]@{
                Name = 'DirectoryServicesRestoreMode LocalAdmin Backdoor Enabled'
                Risk = 'High'
                Source = 'Registry'
                Technique = "T1003.003: OS Credential Dumping"
                Meta = [PSCustomObject]@{
                    Location = $path
                    EntryName = $_.Name
                    EntryValue = $_.Value
                }
                Reference = "https://adsecurity.org/?p=1785"
            }
            
            Write-Detection $detection
        }
    }
}