
function Test-IFEO {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Image File Execution Options"
	$path = "Registry::$regtarget_hklm`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.Debugger -ne $null) {
				Write-SnapshotMessage -Key $item.Name -Value $data.Debugger -Source 'IFEO'

				if ($loadsnapshot) {
					$detection = [PSCustomObject]@{
						Name      = 'Allowlist Mismatch: IFEO Debugger'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
						Meta      = "Registry Path: " + $item.Name + ", Debugger: " + $data.Debugger
					}
					$result = Assert-IsAllowed $allowtable_ifeodebuggers $item.Name $data.Debugger $detection
					if ($result -eq $true) {
						continue
					}
				}
				$detection = [PSCustomObject]@{
					Name      = 'Potential Image File Execution Option Debugger Injection'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
					Meta      = "Registry Path: " + $item.Name + ", Debugger: " + $data.Debugger
				}
				Write-Detection $detection
			}
		}
	}
}
