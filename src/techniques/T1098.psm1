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
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking RDP Shadow Consent")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Shadow' -and ($_.Value -eq 4 -or $_.Value -eq 2)) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'RDPShadow'), $true)) {
					continue
				}

				$detection = [PSCustomObject]@{
					Name      = 'RDP Shadowing without Consent is Enabled'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1098: Account Manipulation"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}