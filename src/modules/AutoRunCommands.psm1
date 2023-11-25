
function Test-CommandAutoRunProcessors {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	
	$State.WriteMessage("Checking Command AutoRun Processors")
	$path = "Registry::$($State.DriveTargets.Hklm)`SOFTWARE\Microsoft\Command Processor"

	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -ne 'AutoRun' -or $State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'CommandAutorunProcessor'), $true)) {
				continue
			}
			
			$State.WriteDetection([TrawlerDetection]::new(
					'Potential Hijacking of Command AutoRun Processor',
					[TrawlerRiskPriority]::VeryHigh,
					'Registry',
					"T1546: Event Triggered Execution",
					[PSCustomObject]@{
						KeyLocation = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor'
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				))
		}
	}

	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Command Processor"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (-not (Test-Path -Path $path)) {
			continue 
		}

		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -ne 'AutoRun' -or $State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'CommandAutorunProcessor'), $true)) {
				continue
			}
			
			$State.WriteDetection([TrawlerDetection]::new(
					'Potential Hijacking of Command AutoRun Processor',
					[TrawlerRiskPriority]::VeryHigh,
					'Registry',
					"T1546: Event Triggered Execution",
					[PSCustomObject]@{
						KeyLocation = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor'
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				))
		}
	}
}
