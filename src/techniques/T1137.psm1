function Test-T1137 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-OfficeGlobalDotName $State
	Test-OfficeTest $State
	Test-OutlookStartup $State
	Test-OfficeTrustedLocations $State
}

function Test-OfficeGlobalDotName {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Office GlobalDotName usage")
	# TODO - Cleanup Path Referencing, Add more versions?
	$office_versions = @(14, 15, 16)
	foreach ($version in $office_versions) {
		$basepath = "Registry::HKEY_CURRENT_USER\software\microsoft\office\$version.0\word\options"
		foreach ($p in $regtarget_hkcu_list) {
			$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
			if (-not (Test-Path -Path $path)) {
				continue 
			}
			
			Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
				if ($_.Name -eq "GlobalDotName") {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'GlobalDotName'), $true)) {
						continue
					}

					$detection = [PSCustomObject]@{
						Name      = 'Persistence via Office GlobalDotName'
						Risk      = [TrawlerRiskPriority]::VeryHigh
						Source    = 'Office'
						Technique = "T1137.001: Office Application Office Template Macros"
						Meta      = "Key Location: HKCU\software\microsoft\office\$version.0\word\options, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					$State.WriteDetection($detection)
				}
			}
		}
	}
}

function Test-OfficeTest {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Office test usage")
	$basepath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (-not (Test-Path -Path $path)) {
			continue 
		}
			Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
				$detection = [PSCustomObject]@{
					Name      = 'Persistence via Office test\Special\Perf Key'
					Risk      = [TrawlerRiskPriority]::VeryHigh
					Source    = 'Office'
					Technique = "T1137.002: Office Application Startup: Office Test"
					Meta      = "Key Location: HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf: " + $_.Name + ", Entry Value: " + $_.Value
				}
				$State.WriteDetection($detection)
			}
	}

	$path = "Registry::$($State.DriveTargets.Hklm)Software\Microsoft\Office test\Special\Perf"
	if (Test-Path -Path $path) {
		Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
			$detection = [PSCustomObject]@{
				Name      = 'Persistence via Office test\Special\Perf Key'
				Risk      = [TrawlerRiskPriority]::VeryHigh
				Source    = 'Office'
				Technique = "T1137.002: Office Application Startup: Office Test"
				Meta      = "Key Location: HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
			}

			$State.WriteDetection($detection)
		}
	}
}

function Test-OutlookStartup {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Outlook Macros")
	# allowlist_officeaddins
	$profile_names = Get-ChildItem "$($State.DriveTargets.HomeDrive)\Users" -Attributes Directory | Select-Object *
	foreach ($user in $profile_names) {
		$path = "$($State.DriveTargets.HomeDrive)\Users\" + $user.Name + "\AppData\Roaming\Microsoft\Word\STARTUP"
		$items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object { $_.extension -in $office_addin_extensions }
		# Removing this as we are performing this functionality else-where for Office Trusted Location Scanning.
		#foreach ($item in $items){
		#	if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.FullName, $item.FullName, 'Office'), $true)) {
		continue
	}

	# If the allowlist contains the curren task name
	#    if ($loadsnapshot -and ($allowlist_outlookstartup.Contains($item.FullName))){
	#        continue
	#    }

	#    $detection = [PSCustomObject]@{
	#        Name = 'Potential Persistence via Office Startup Addin'
	#        Risk = [TrawlerRiskPriority]::Medium
	#        Source = 'Office'
	#        Technique = "T1137.006: Office Application Startup: Add-ins"
	#        Meta = "File: "+$item.FullName+", Last Write Time: "+$item.LastWriteTime
	#    }
	#$State.WriteDetection($detection) - Removing this as it is a duplicate of the new Office Scanning Functionality which will cover the same checks
	#}
	$path = "$($State.DriveTargets.HomeDrive)\Users\" + $user.Name + "\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM"
	if (Test-Path $path) {
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($path, $item.FullName, 'Outlook'), $true)) {
			continue
		}

		$detection = [PSCustomObject]@{
			Name      = 'Potential Persistence via Outlook Application Startup'
			Risk      = [TrawlerRiskPriority]::Medium
			Source    = 'Office'
			Technique = "T1137.006: Office Application Startup: Add-ins"
			Meta      = "File: " + $path
		}
		$State.WriteDetection($detection)
	}
}


function Test-OfficeTrustedLocations {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Mostly supports drive retargeting
	# https://github.com/PowerShell/PowerShell/issues/16812
	$State.WriteMessage("Checking Office Trusted Locations")
	#TODO - Add 'abnormal trusted location' detection
	$profile_names = Get-ChildItem "$($State.DriveTargets.HomeDrive)\Users" -Attributes Directory | Select-Object *
	$actual_current_user = $env:USERNAME
	$user_pattern = "$($State.DriveTargets.AssumedHomeDrive)\\Users\\(.*?)\\.*"
	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$possible_paths = New-Object -TypeName "System.Collections.ArrayList"
			foreach ($item in $items) {
				$path = "Registry::" + $item.Name
				$data = Get-TrawlerItemProperty -Path $path
				if ($data.Path) {
					$possible_paths.Add($data.Path) | Out-Null
					$currentcaptureduser = [regex]::Matches($data.Path, $user_pattern).Groups.Captures.Value
					if ($currentcaptureduser) {
						$current_user = $currentcaptureduser[1]
					}
					else {
						$current_user = 'NO_USER_FOUND_IN_PATH'
					}
					if ($data.Path.Contains($current_user)) {
						foreach ($user in $profile_names) {
							$new_path = $data.Path.replace($current_user, $user.Name)
							#Write-Host $new_path
							if ($possible_paths -notcontains $new_path) {
								$possible_paths.Add($new_path) | Out-Null
							}
						}
					}


					$default_trusted_locations = @(
						"C:\Users\$actual_current_user\AppData\Roaming\Microsoft\Templates"
						"C:\Program Files\Microsoft Office\root\Templates\"
						"C:\Program Files (x86)\Microsoft Office\root\Templates\"
						"C:\Users\$actual_current_user\AppData\Roaming\Microsoft\Word\Startup"
					)
					$pass = $false
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($data.Path, $data.Path, 'OfficeTrustedLocations'), $true)) {
						continue
					}

					if ('{0}' -f $data.Path -notin $default_trusted_locations -and $pass -eq $false) {
						$p = $data.Path
						$detection = [PSCustomObject]@{
							Name      = 'Non-Standard Office Trusted Location'
							Risk      = [TrawlerRiskPriority]::Medium
							Source    = 'Office'
							Technique = "T1137.006: Office Application Startup: Add-ins"
							Meta      = "Location: $p"
						}
						$State.WriteDetection($detection)
						# TODO - Still working on this - can't read registry without expanding the variables right now
						# https://github.com/PowerShell/PowerShell/issues/16812
						#
					}
				}
			}
		}
	}

	foreach ($p in $possible_paths) {
		if (Test-Path $p) {
			$items = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Select-Object * | Where-Object { $_.extension -in $office_addin_extensions }
			foreach ($item in $items) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.FullName, $item.FullName, 'OfficeAddins'), $true)) {
					continue
				}

				$detection = [PSCustomObject]@{
					Name      = 'Potential Persistence via Office Startup Addin'
					Risk      = [TrawlerRiskPriority]::Medium
					Source    = 'Office'
					Technique = "T1137.006: Office Application Startup: Add-ins"
					Meta      = "File: " + $item.FullName + ", Last Write Time: " + $item.LastWriteTime
				}
				$State.WriteDetection($detection)
			}
		}
	}
}