function Test-BootVerificationProgram {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)

	$State.WriteMessage("Checking BootVerificationProgram")
	$path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Control\BootVerificationProgram"
	if (-not (Test-Path -Path $path)) {
		return
	}
	
	$data = Get-TrawlerItemProperty -Path $path

	if ($data.ImagePath) {
		$snapShotData = [TrawlerSnapShotData]::new(
			"ImagePath",
			$data.ImagePath,
			'BootVerificationProgram'
		)

		if ($State.IsExemptBySnapShot($snapShotData, $true)) {
			return
		}

		$State.WriteDetection(
			'BootVerificationProgram will launch associated program as a service on startup.',
			[TrawlerRiskPriority]::High,
			'Registry',
			"T1112: Modify Registry",
			[PSCustomObject]@{
				RegistryPath = $path
				Program = $data.ImagePath
			}
		)
	}
}