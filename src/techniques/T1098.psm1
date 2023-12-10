function Test-T1098 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-RDPShadowConsent $State
}

function Test-RDPShadowConsent {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking RDP Shadow Consent")
	$path = "Registry::$($State.Drives.Hklm)SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
	if (Test-Path -Path $path) {
		Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
			if ($_.Name -eq 'Shadow' -and ($_.Value -eq 4 -or $_.Value -eq 2)) {
				if ($State.IsExemptBySnapShot($_.Name, $_.Value, 'RDPShadow')) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'RDP Shadowing without Consent is Enabled',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1098: Account Manipulation",
					[PSCustomObject]@{
						KeyLocation = $path
						EntryName   = $_.Name
						EntryKey    = $_.Value
					}
				)
				
				$State.WriteDetection($detection)
			}
		}
	}
}