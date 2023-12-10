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
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Office GlobalDotName usage")
	# TODO - Cleanup Path Referencing, Add more versions?
	$office_versions = @(14, 15, 16)
	foreach ($version in $office_versions) {
		$basepath = "Registry::{0}\software\microsoft\office\$version.0\word\options"
		foreach ($p in $State.GetFormattedUserPaths($basepath)) {
			Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
				if ($_.Name -eq "GlobalDotName") {
					if ($State.IsExemptBySnapShot($_.Name, $_.Value, 'GlobalDotName')) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'Persistence via Office GlobalDotName',
						[TrawlerRiskPriority]::VeryHigh,
						'Office',
						"T1137.001: Office Application Office Template Macros",
						[PSCustomObject]@{
							KeyLocation = "HKCU\software\microsoft\office\$version.0\word\options"
							EntryName   = $_.Name
							EntryValue  = $_.Value
						}
					)
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
		[object]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Office test usage")
	$basepath = "Registry::{0}\Software\Microsoft\Office test\Special\Perf"
	foreach ($p in $State.GetFormattedUserPaths($basepath)) {
		Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
			$detection = [TrawlerDetection]::new(
				'Persistence via Office test\Special\Perf Key',
				[TrawlerRiskPriority]::VeryHigh,
				'Office',
				"T1137.002: Office Application Startup: Office Test",
				[PSCustomObject]@{
					KeyLocation = "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf"
					EntryName   = $_.Name
					EntryValue  = $_.Value
				}
			)
			$State.WriteDetection($detection)
		}
	}

	$path = "Registry::$($State.Drives.Hklm)Software\Microsoft\Office test\Special\Perf"
	if (Test-Path -Path $path) {
		Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
			$detection = [TrawlerDetection]::new(
				'Persistence via Office test\Special\Perf Key',
				[TrawlerRiskPriority]::VeryHigh,
				'Office',
				"T1137.002: Office Application Startup: Office Test",
				[PSCustomObject]@{
					KeyLocation = "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf"
					EntryName   = $_.Name
					EntryValue  = $_.Value
				}
			)

			$State.WriteDetection($detection)
		}
	}
}

function Test-OutlookStartup {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Outlook Macros")

	$path = "$($State.Drives.HomeDrive)\Users\" + $user.Name + "\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM"
	if (-not (Test-Path $path)) {
		return 
	}

	if ($State.IsExemptBySnapShot($path, $item.FullName, 'Outlook')) {
		return
	}

	$detection = [TrawlerDetection]::new(
		'Potential Persistence via Outlook Application Startup',
		[TrawlerRiskPriority]::Medium,
		'Office',
		"T1137.006: Office Application Startup: Add-ins",
		[PSCustomObject]@{
			File = $path
		}
	)

	$State.WriteDetection($detection)
}


function Test-OfficeTrustedLocations {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Mostly supports drive retargeting
	# https://github.com/PowerShell/PowerShell/issues/16812
	$State.WriteMessage("Checking Office Trusted Locations")
	#TODO - Add 'abnormal trusted location' detection
	$profile_names = Get-ChildItem "$($State.Drives.HomeDrive)\Users" -Attributes Directory | Select-Object *
	$actual_current_user = $env:USERNAME
	$user_pattern = "$($State.Drives.AssumedHomeDrive)\\Users\\(.*?)\\.*"
	$basepath = "Registry::{0}\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations"

	foreach ($p in $State.GetFormattedUserPaths($basepath)) {
		$items = Get-TrawlerItemData -Path $path -ItemType ChildItem
		$possible_paths = New-Object -TypeName "System.Collections.ArrayList"

		foreach ($item in $items) {
			$data = Get-TrawlerItemData -Path $path -ItemType ItemProperty -AsRegistry
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

				if ($State.IsExemptBySnapShot($data.Path, $data.Path, 'OfficeTrustedLocations')) {
					continue
				}

				if ($data.Path -notin $default_trusted_locations) {
					$p = $data.Path
					$detection = [TrawlerDetection]::new(
						'Non-Standard Office Trusted Location',
						[TrawlerRiskPriority]::Medium,
						'Office',
						"T1137.006: Office Application Startup: Add-ins",
						[PSCustomObject]@{
							Location = $p
						}
					)
					$State.WriteDetection($detection)
					# TODO - Still working on this - can't read registry without expanding the variables right now
					# https://github.com/PowerShell/PowerShell/issues/16812
					#
				}
			}
		}
	}

	foreach ($p in $possible_paths) {
		if (Test-Path $p) {
			$items = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, Extension
			foreach ($item in $items) {
				if (-not (Test-OfficeExtension -Value $item.Extension)) {
					continue
				}

				if ($State.IsExemptBySnapShot($item.FullName, $item.FullName, 'OfficeAddins')) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'Potential Persistence via Office Startup Addin',
					[TrawlerRiskPriority]::Medium,
					'Office',
					"T1137.006: Office Application Startup: Add-ins",
					($item | Select-Object FullName, LastWriteTime)
				)

				$State.WriteDetection($detection)
			}
		}
	}
}