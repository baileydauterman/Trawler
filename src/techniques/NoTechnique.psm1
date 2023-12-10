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
	$knownPaths = @(
		"{0}\Users\Public"
		"{0}\Users\Administrator"
		"{0}\Windows\temp"
	)

	foreach ($path in $State.GetFormattedTargetDrivePaths($knownPaths)) {
		foreach ($item in Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Include $suspicious_extensions) {
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