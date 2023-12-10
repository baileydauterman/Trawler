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
		[object]
		$State
	)

	$State.WriteMessage("Checking DNSServerLevelPlugin DLL")

	$path = "Registry::{0}SYSTEM\{1}\Services\DNS\Parameters"
	$path = $State.GetFormattedHklmControlSetPath($path)
	if (-not (Test-Path -Path $path)) {
		return 
	}

	Get-TrawlerItemData -Path $path -ItemType ItemProperty | Where-Object Name -eq "ServerLevelPluginDll" | Where-Object Value -ne '""' | ForEach-Object {
		if ($State.IsExemptBySnapShot($_.Name, $_.Value, 'DNSPlugin')) {
			continue
		}

		$detection = [TrawlerDetection]::new(
			'Review: DNS ServerLevelPluginDLL is active',
			[TrawlerRiskPriority]::Medium,
			'Registry',
			"T1055.001: Process Injection: Dynamic-link Library Injection",
			[PSCustomObject]@{
				KeyLocation = $path
				EntryName   = $_.Name
				DLL         = $_.Value
			}
		)

		$State.WriteDetection($detection)
	}
}