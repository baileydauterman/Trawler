function Test-NoTechnique {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	Test-SuspiciousFileLocations $State
}

function Test-SuspiciousFileLocations {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	$State.WriteMessage("Checking Suspicious File Locations")
	$suspicious_extensions = @('*.exe', '*.bat', '*.ps1', '*.hta', '*.vb', '*.vba', '*.vbs', '*.zip', '*.gz', '*.7z', '*.dll', '*.scr', '*.cmd', '*.com', '*.ws', '*.wsf', '*.scf', '*.scr', '*.pif')
	$recursive_paths_to_check = @(
		"$($State.Drives.HomeDrive)\Users\Public"
		"$($State.Drives.HomeDrive)\Users\Administrator"
		"$($State.Drives.HomeDrive)\Windows\temp"
	)
	foreach ($path in $recursive_paths_to_check) {
		$items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Include $suspicious_extensions
		foreach ($item in $items) {
			$State.WriteDetection([TrawlerDetection]::new(
				'Anomalous File in Suspicious Location',
				[TrawlerRiskPriority]::High,
				'Windows',
				"N/A",
				($item | Select-Object FullName, CreationTime, LastWriteTime)
			))
		}
	}
}