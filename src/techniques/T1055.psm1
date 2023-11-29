function Test-T1055 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-DNSServerLevelPluginDLL $State
}

<#
# Start TT1055.001
#>

function Test-DNSServerLevelPluginDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking DNSServerLevelPlugin DLL")
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Services\DNS\Parameters"
	if (-not (Test-Path -Path $path)) {
		return 
	}

	Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
		if ($_.Name -eq 'ServerLevelPluginDll' -and $_.Value -ne '""') {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'DNSPlugin'), $true)) {
				continue
			}

			$detection = [PSCustomObject]@{
				Name      = 'Review: DNS ServerLevelPluginDLL is active'
				Risk      = [TrawlerRiskPriority]::Medium
				Source    = 'Registry'
				Technique = "T1055.001: Process Injection: Dynamic-link Library Injection"
				Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", DLL: " + $_.Value
			}
			$State.WriteDetection($detection)
		}
	}
}