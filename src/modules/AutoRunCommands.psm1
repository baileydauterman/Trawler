
function Test-CommandAutoRunProcessors {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Command AutoRun Processors"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Command Processor"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AutoRun') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'CommandAutorunProcessor'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_cmdautorunproc $_.Value $_.Value
					if ($result -eq $true) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential Hijacking of Command AutoRun Processor'
						Risk      = 'Very High'
						Source    = 'Registry'
						Technique = "T1546: Event Triggered Execution"
						Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Command Processor"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'AutoRun') {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'CommandAutorunProcessor'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_cmdautorunproc $_.Value $_.Value
						if ($result -eq $true) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Potential Hijacking of Command AutoRun Processor'
							Risk      = 'Very High'
							Source    = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Key Location: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Command Processor, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}
