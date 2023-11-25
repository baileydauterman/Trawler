function Test-BootVerificationProgram {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking BootVerificationProgram"
	$path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Control\BootVerificationProgram"
	if (Test-Path -Path $path) {
		$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		if ($data.ImagePath -ne $null) {
			Write-SnapshotMessage -Key "ImagePath" -Value $data.ImagePath -Source 'BootVerificationProgram'

			if ($loadsnapshot) {
				$result = Check-AllowList $allowlist_bootverificationprogram "ImagePath" $data.ImagePath
				if ($result) {
					continue
				}
			}
			$detection = [PSCustomObject]@{
				Name      = 'BootVerificationProgram will launch associated program as a service on startup.'
				Risk      = 'High'
				Source    = 'Registry'
				Technique = "T1112: Modify Registry"
				Meta      = "Registry Path: " + $path + ", Program: " + $data.ImagePath
			}
			Write-Detection $detection
		}
	}
}