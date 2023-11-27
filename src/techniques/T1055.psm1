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
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Services\DNS\Parameters"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ServerLevelPluginDll' -and $_.Value -ne '""') {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'DNSPlugin'), $true)) {
							continue
						}

				$detection = [PSCustomObject]@{
					Name      = 'Review: DNS ServerLevelPluginDLL is active'
					Risk      = 'Medium'
					Source    = 'Registry'
					Technique = "T1055.001: Process Injection: Dynamic-link Library Injection"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", DLL: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}