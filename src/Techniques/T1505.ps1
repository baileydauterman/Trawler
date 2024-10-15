function Check-TerminalServicesDLL {
    # Supports Drive Retargeting
    Write-Message "Checking TerminalServices DLL"
    $path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Services\TermService\Parameters"

    Get-TrawlerItemPropertyProperties $path | Where-Object Name -eq "ServiceDll" | Where-Object Value -ne 'C:\Windows\System32\termsrv.dll' | ForEach-Object {
        $detection = [PSCustomObject]@{
            Name      = 'Potential Hijacking of Terminal Services DLL'
            Risk      = 'Very High'
            Source    = 'Registry'
            Technique = "T1505.005: Server Software Component: Terminal Services DLL"
            Meta      = [PSCustomObject]@{
                Location   = $path
                EntryName  = $_.Name
                EntryValue = $_.Value
                Hash       = Get-File-Hash $_.Value
            }
        }
        Write-Detection $detection
    }
}