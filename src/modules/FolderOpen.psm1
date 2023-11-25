
function Check-FolderOpen {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking FolderOpen Command"
	$basepath = "Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open\command"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'DelegateExecute') {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'FolderOpen'

					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_folderopen $_.Value $_.Value
						if ($result -eq $true) {
							return
						}
					}
					$detection = [PSCustomObject]@{
						Name      = 'Potential Folder Open Hijack for Persistence'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
						Meta      = "Key Location: HKCU\Software\Classes\Folder\shell\open\command, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}


