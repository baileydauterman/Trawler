function Test-NoTechnique {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)

	Test-SuspiciousFileLocations $State
}

function Test-SuspiciousFileLocations {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
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
			$detection = [PSCustomObject]@{
				Name      = 'Anomalous File in Suspicious Location'
				Risk      = [TrawlerRiskPriority]::High
				Source    = 'Windows'
				Technique = "N/A"
				Meta      = "File: " + $item.FullName + ", Created: " + $item.CreationTime + ", Last Modified: " + $item.LastWriteTime
			}
			$State.WriteDetection($detection)
		}
	}
}