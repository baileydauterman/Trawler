
function Test-ApplicationShims {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Application Shims"
	# TODO - Also check HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppShims'

			$pass = $false
			if ($loadsnapshot) {
				$result = Assert-IsAllowed $allowlist_appshims $_.Value $_.Value
				if ($result -eq $true) {
					$pass = $true
				}
			}
			if ($pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Application Shimming Persistence'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546.011: Event Triggered Execution: Application Shimming"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
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
				
			$snapShot = [TrawlerSnapShotData]::new($item.Name, $_.Value, 'AppPaths')
			$State.WriteSnapShotMessage($snapShot)

			if ($State.IsExemptBySnapShot($snapShot)) {
				continue
			}

			$State.WriteDetection([TrawlerDetection]::new(
					'Allowlist Mismatch: Potential App Path Hijacking - Executable Name does not match Registry Key',
					'Medium',
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
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Startup Items"
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
	}
 else {
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
		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_startup_commands $item.Command $item.Command)) {
			continue
		}

		Write-SnapshotMessage -Key $item.Name -Value $item.Command -Source 'Startup'

		$detection = [PSCustomObject]@{
			Name      = 'Startup Item Review'
			Risk      = 'Low'
			Source    = 'Startup'
			Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
			Meta      = "Location: " + $item.Location + ", Item Name: " + $item.Name + ", Command: " + $item.Command + ", User: " + $item.User
		}

		Write-Detection $detection
	}

	foreach ($path_ in $paths) {
		#Write-Host $path
		$path = "Registry::$path_"
		if (Test-Path -Path $path) {
			$item = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -ne "(Default)") {
					if ($loadsnapshot -and ($allowlist_startup_commands.Contains($_.Value))) {
						continue
					}

					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'Startup'
					
					$detection = [PSCustomObject]@{
						Name      = 'Startup Item Review'
						Risk      = 'Low'
						Source    = 'Startup'
						Technique = "T1037.005: Boot or Logon Initialization Scripts: Startup Items"
						Meta      = "Location: $path_, Item Name: " + $_.Name + ", Command: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}
