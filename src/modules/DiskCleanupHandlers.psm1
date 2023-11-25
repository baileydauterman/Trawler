function Test-DiskCleanupHandlers {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Retargeting/Snapshot
	Write-Message "Checking DiskCleanupHandlers"
	$default_cleanup_handlers = @(
		"C:\Windows\System32\DATACLEN.DLL",
		"C:\Windows\System32\PeerDistCleaner.dll",
		"C:\Windows\System32\D3DSCache.dll",
		"C:\Windows\system32\domgmt.dll",
		"C:\Windows\System32\pnpclean.dll",
		"C:\Windows\System32\occache.dll",
		"C:\Windows\System32\ieframe.dll",
		"C:\Windows\System32\LanguagePackDiskCleanup.dll",
		"C:\Windows\system32\setupcln.dll",
		"C:\Windows\system32\shell32.dll",
		"C:\Windows\system32\wmp.dll",
		"C:\Windows\System32\thumbcache.dll",
		"C:\Windows\system32\scavengeui.dll",
		"C:\Windows\System32\fhcleanup.dll"
	)
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
	if (Test-Path -LiteralPath "Registry::$path") {
		$items = Get-TrawlerChildItem "Registry::$path"
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty $path
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(Default)') {
					$target_prog = ''
					$tmp_path = "$regtarget_hkcr`CLSID\$($_.Value)\InProcServer32"
					if (Test-Path -LiteralPath "Registry::$tmp_path") {
						$data_tmp = Get-TrawlerItemProperty "Registry::$tmp_path"
						$data_tmp.PSObject.Properties | ForEach-Object {
							if ($_.Name -eq '(Default)') {
								$target_prog = $_.Value
							}
						}
					}
					if ($target_prog -in $default_cleanup_handlers) {
						continue
					}
					Write-SnapshotMessage -Key $item.Name -Value $target_prog -Source 'DiskCleanupHandlers'
					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_diskcleanuphandlers $_.target_prog $_.target_prog
						if ($result) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Non-Default DiskCleanupHandler Program'
							Risk      = 'Low'
							Source    = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Key: " + $item.Name + ", Program: " + $target_prog
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}