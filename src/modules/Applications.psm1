
function Test-ApplicationShims {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)

	$State.WriteMessage("Checking Application Shims")
	# TODO - Also check HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"
	if (-not (Test-Path -Path $path)) {
		return 
	}
	$items = Get-TrawlerItemProperty -Path $path
	$items.PSObject.Properties | ForEach-Object {
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'AppShims'), $true)) {
			continue
		}

		$State.WriteDetection([TrawlerDetection]::new(
				'Potential Application Shimming Persistence',
				[TrawlerRiskPriority]::High,
				'Registry',
				"T1546.011: Event Triggered Execution: Application Shimming",
				[PSCustomObject]@{
					KeyLocation = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"
					EntryName   = $_.Name
					EntryValue  = $_.Value
				}
			))
	}
}


function Test-AppPaths {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)

	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking AppPaths")
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"

	if (-not (Test-TrawlerPath -Path $path -AsRegistry)) {
		return
	}

	foreach ($item in Get-TrawlerChildItem -Path $path -AsRegistry) {
		$data = Get-TrawlerItemProperty -Path $item.Name -AsRegistry
		$data.PSObject.Properties | ForEach-Object {
			if ($_.Name -ne '(default)') {
				continue
			}

			$key_basename = [regex]::Matches($item.Name, ".*\\(?<name>[^\\].*)").Groups.Captures.Value[1]
			$value_basename = [regex]::Matches($_.Value, ".*\\(?<name>[^\\].*)").Groups.Captures.Value[1]

			# if one or more regex doesn't match, continue on
			if ($key_basename -and $value_basename) {
				continue
			}

			$value_basename = $value_basename.Replace('"', "")

			if ($key_basename -ne $value_basename) {
				contine
			}

			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $_.Value, 'AppPaths'), $true)) {
				continue
			}

			$State.WriteDetection([TrawlerDetection]::new(
					'Allowlist Mismatch: Potential App Path Hijacking - Executable Name does not match Registry Key',
					[TrawlerRiskPriority]::Medium,
					'Registry',
					"T1546: Event Triggered Execution",
					[PSCustomObject]@{
						KeyLocation = $item.Name
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				))
		}
	}
}

function Test-Startups {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Startup Items")
	$paths = @(
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
		"$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
	)
	if ($nevermind) {
		foreach ($tmpbase in $paths) {
			if ($tmpbase -match "REPLACE.*") {
				foreach ($p in $regtarget_hkcu_list) {
					$newpath = $tmpbase.Replace("REPLACE", $p)
					$paths += $newpath
				}
			}
		}
		$startups = @()
	} else {
		$startups = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Command, Location, Name, User
		#$statups = @()

	}
	# Redoing this to only read reg-keys instead of using win32_StartupCommand
	foreach ($tmpbase in $paths) {
		if ($tmpbase -match "REPLACE.*") {
			foreach ($p in $regtarget_hkcu_list) {
				$newpath = $tmpbase.Replace("REPLACE", $p)
				$paths += $newpath
			}
		}
	}
	$startups = @()

	foreach ($item in $startups) {
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $item.Command, 'Startup'), $true)) {
			continue
		}

		$State.WriteDetection([TrawlerDetection]::new(
				'Startup Item Review',
				[TrawlerRiskPriority]::Low,
				'Startup',
				"T1037.005: Boot or Logon Initialization Scripts: Startup Items",
				($item | Select-Object Location, Name, Command, User)
			))
	}

	foreach ($path_ in $paths) {
		$path = $State.PathAsRegistry($path_)
		if (-not (Test-Path -Path $path)) {
			continue
		}

		$item = Get-TrawlerItemProperty -Path $path
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "(Default)" -or $State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'Startup'), $true)) {
				continue
			}
			
			$State.WriteDetection([TrawlerDetection]::new(
					'Startup Item Review',
					[TrawlerRiskPriority]::Low,
					'Startup',
					"T1037.005: Boot or Logon Initialization Scripts: Startup Items",
					[PSCustomObject]@{
						Location = $path_
						ItemName = $_.Name
						Command  = $_.Value
					}
				))
		}
	}
}
