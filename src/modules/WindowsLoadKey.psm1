
function Test-WindowsLoadKey {
	# TODO - Add Snapshot Skipping
	# Supports Drive Retargeting
	Write-Message "Checking Windows Load"
	$basepath = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path "Registry::$path") {
			$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -in 'Load') {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'WindowsLoad'

					$detection = [PSCustomObject]@{
						Name      = 'Potential Windows Load Hijacking'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1546: Event Triggered Execution"
						Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}
