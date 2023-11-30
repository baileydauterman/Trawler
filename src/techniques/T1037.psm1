function Test-T1037 {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
    
	Test-Startups $State
	Test-GPOScripts $State
	Test-TerminalProfiles $State
	Test-UserInitMPRScripts $State
}

function Test-Startups {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Startup Items")
	$paths = @(
		"$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		"$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		"$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
		"$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
		"$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
		"REPLACE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
	)
	if ($nevermind) {
		foreach ($tmpbase in $paths) {
			if ($tmpbase -match "REPLACE.*") {
				foreach ($p in $State.Drives.CurrentUsers) {
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
			foreach ($p in $State.Drives.CurrentUsers) {
				$newpath = $tmpbase.Replace("REPLACE", $p)
				$paths += $newpath
			}
		}
	}
	$startups = @()

	foreach ($item in $startups) {
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $item.Command, 'Startup'))) {
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

		Get-TrawlerItemPropertyObjectProperties -Path $path | ForEach-Object {
			if ($_.Name -eq "(Default)" -or $State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'Startup'))) {
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

function Test-GPOScripts {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking GPO Scripts")

	$paths = @(
		$State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "Machine", "Scripts", "psscripts.ini"))
		$State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "Machine", "Scripts", "scripts.ini")),
		$State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "User", "Scripts", "psscripts.ini")),
		$State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "User", "Scripts", "scripts.ini"))
	)

	$path_lookup = @{
		Startup  = $State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "Machine", "Scripts", "Startup"))
		Shutdown = $State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "Machine", "Scripts", "Shutdown"))
		Logoff   = $State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "User", "Scripts", "Logoff"))
		Logon    = $State.ToTargetDrivePath(@("Windows", "System32", "GroupPolicy", "User", "Scripts", "Logon"))
	}

	foreach ($path in $paths) {
		# Skip non-existent files
		if (-not (Test-Path $path)) {
			return
		}

		$content = Get-Content $path
		$script_type = ""
		foreach ($line in $content) {
			if ($line.Trim() -eq "") {
				continue
			}

			switch ($line) {
				"[Shutdown]" { $script_type = "Shutdown" }
				"[Startup]" { $script_type = "Startup" }
				"[Logon]" { $script_type = "Logon" }
				"[Logoff]" { $script_type = "Logoff" }
				Default {}
			}

			switch -Regex ($line) {
				"\d{1,9}CmdLine=" { $cmdline = $line.Split("=", 2)[1] }
				"\d{1,9}Parameters=" { $params = $line.Split("=", 2)[1] }
			}

			if ($params) {
				# Last line in each script descriptor is the Parameters
				if ($script_type -eq "Shutdown" -or $script_type -eq "Startup") {
					$desc = "Machine $script_type Script"
				}
				elseif ($script_type -eq "Logon" -or $script_type -eq "Logoff") {
					$desc = "User $script_type Script"
				}

				$script_location = $cmdline
				if ($cmdline -notmatch "[A-Za-z]{1}:\\.*") {
					$script_location = $path_lookup[$script_type] + $cmdline
				}

				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($script_location, $script_location, 'GPOScripts'))) {
					$cmdline = $null
					$params = $null
					continue
				}

				# TODO - Figure out ERROR
				$script_content_detection = $false
				try {
					foreach ($line_ in Get-Content $script_location) {
						if ($line_ -match $State.SuspiciousTerms -and $script_content_detection -eq $false) {
							$State.WriteDetection([TrawlerDetection]::new(
									"Suspicious Content in $desc",
									[TrawlerRiskPriority]::High,
									'Windows GPO Scripts',
									"T1037: Boot or Logon Initialization Scripts",
									[PSCustomObject]@{
										File           = $script_location
										Arguments      = $params
										SuspiciousLine = $line_
									}
								))
							$script_content_detection = $true
						}
					}
				}
				catch {
				}
				# no suspicious lines but should still be investigated
				if (-not $script_content_detection) {
					$State.WriteDetection([TrawlerDetection]::new(
							"Review: $desc",
							[TrawlerRiskPriority]::Medium,
							'Windows GPO Scripts',
							"T1037: Boot or Logon Initialization Scripts",
							[PSCustomObject]@{
								File      = $script_location
								Arguments = $params
							}
						))
				}

				$cmdline = $null
				$params = $null
			}

		}
	}
}

function Test-TerminalProfiles {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	$State.WriteMessage("Checking Terminal Profiles")

	$base_path = $State.ToTargetDrivePath(@("Users", "_USER_", "AppData", "Local", "Packages"))

	foreach ($user in Get-ChildItem ($State.ToTargetDrivePath("Users")) -Directory) {
		$userPath = $base_path.replace("_USER_", $user.Name)
		$terminalDirs = Get-ChildItem $userPath -Filter "Microsoft.WindowsTerminal*" -ErrorAction SilentlyContinue
		foreach ($dir in $terminalDirs) {
			if (-not (Test-Path "$dir\LocalState\settings.json")) {
				continue
			}

			$terminalSettings = Get-Content -Raw "$dir\LocalState\settings.json" | ConvertFrom-Json
			if ($terminalSettings.startOnUserLogin -or $terminalSettings.startOnUserLogin -ne $true) {
				continue
			}

			$defaultGUID = $terminalSettings.defaultProfile
			foreach ($profile_list in $terminalSettings.profiles) {
				foreach ($profile in $profile_list.List) {
					if ($profile.guid -eq $defaultGUID) {
						if ($profile.commandline) {
							$exe = $profile.commandline
						}
						else {
							$exe = $profile.name
						}

						$userTerminalSettings = "$dir\LocalState\settings.json"

						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($userTerminalSettings, $exe, "TerminalUserProfile"))) {
							continue
						}

						$State.WriteDetection([TrawlerDetection]::new(
								'Windows Terminal launching command on login',
								[TrawlerRiskPriority]::Medium,
								'Terminal',
								"T1037: Boot or Logon Initialization Scripts",
								[PSCustomObject]@{
									File    = $userTerminalSettings
									Command = $exe
								}
							))
					}
				}
			}
		}
	}
}

<#
# Start T1037.001
#>

function Test-UserInitMPRScripts {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking UserInitMPRLogonScript")
	$basepath = "Registry::HKEY_CURRENT_USER\Environment"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (-not (Test-Path -Path $path)) {
			continue 
		}
		
		Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
			if ($_.Name -ne 'UserInitMprLogonScript') {
				continue 
			}
				
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'UserInitMPR'))) {
				continue
			}

			$State.WriteDetection([TrawlerDetection]::new(
					'Potential Persistence via Logon Initialization Script',
					[TrawlerRiskPriority]::Medium,
					'Registry',
					"T1037.001: Boot or Logon Initialization Scripts: Logon Script (Windows)",
					[PSCustomObject]@{
						KeyLocation = "HKCU\Environment"
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				))
		}
	}
}