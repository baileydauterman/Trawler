function Check-RDPStartupPrograms {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking RDP Startup Programs"
	$allowed_rdp_startups = @(
		"rdpclip"
	)
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Terminal Server\Wds\rdpwd"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'StartupPrograms' -and $_.Value -ne "") {
				$packages = $_.Value.Split(",")
				foreach ($package in $packages) {
					if ($package -notin $allowed_rdp_startups) {
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'RDPStartup'

						$pass = $false
						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_rdpstartup $package $package
							if ($result -eq $true) {
								$pass = $true
							}
						}
						if ($pass -eq $false) {
							$detection = [PSCustomObject]@{
								Name      = 'Non-Standard RDP Startup Program'
								Risk      = 'Medium'
								Source    = 'Registry'
								Technique = "T1574: Hijack Execution Flow"
								Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
							}
							Write-Detection $detection
						}
					}
				}
			}
		}
	}
}

function Check-RDPShadowConsent {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking RDP Shadow Consent"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Shadow') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'RDPShadow'

				if ($loadsnapshot) {
					$detection = [PSCustomObject]@{
						Name      = 'Allowlist Mismatch: RDP Shadowing'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1098: Account Manipulation"
						Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					$result = Assert-IsAllowed $allowtable_rdpshadow $_.Name $_.Value $detection
					if ($result -eq $true) {
						return
					}
				}
			}
			if ($_.Name -eq 'Shadow' -and ($_.Value -eq 4 -or $_.Value -eq 2)) {
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