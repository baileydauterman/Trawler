function Test-T1112 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-AMSIProviders $State
	Test-BootVerificationProgram $State
	Test-NaturalLanguageDevelopmentDLLs $State
	Test-MicrosoftTelemetryCommands $State
	Test-PrintMonitorDLLs $State
	Test-RemoteUACSetting $State
}

function Test-AMSIProviders {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	# TODO - Add Snapshot Skipping
	# Supports Drive Retargeting
	$State.WriteMessage("Checking AMSI Providers")
	$allowedProviders = @(
		"{2781761E-28E0-4109-99FE-B9D127C57AFE}"
	)

	$path = "$($State.DriveTargets.Hklm)\SOFTWARE\Microsoft\AMSI\Providers"
	if (Test-Path -Path $path) {
		foreach ($item in Get-TrawlerChildItem -Path $path -AsRegistry) {
			if ($item.PSChildName -in $allowedProviders) {
				continue
			}

			$new_path = "Registry::HKLM\SOFTWARE\Classes\CLSID\$($item.PSChildName)\InprocServer32"
			if (-not (Test-Path $new_path)) {
				continue
			}
			
			$State.WriteMessage("ASMI Providers checking: $new_path")
			
			$dll_data = Get-ItemProperty -Path $new_path
			foreach ($property in Get-TrawlerItemData -Path $new_path -ItemType ItemProperty) {
				if ($property.Name -ne '(Default)') {
					continue
				}

				$State.WriteSnapShotMessage($property.Name, $property.Value, "AMSI")
				$State.WriteDetection([TrawlerDetection]::new(
						'Non-Standard AMSI Provider DLL',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1112: Modify Registry",
						[PSCustomObject]@{
							KeyLocation = $path
							EntryName   = $_.Name
							EntryValue  = $_.Value
						}
					))	
			}
		}
	}
}

function Test-BootVerificationProgram {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)

	$State.WriteMessage("Checking BootVerificationProgram")
	$path = "Registry::$($State.DriveTargets.Hklm)`SYSTEM\CurrentControlSet\Control\BootVerificationProgram"
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
				Program      = $data.ImagePath
			}
		)
	}
}

function Test-NaturalLanguageDevelopmentDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking NaturalLanguageDevelopment DLLs")
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\CurrentControlSet\Control\ContentIndex\Language"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.StemmerDLLPathOverride -or $data.WBDLLPathOverride) {
				if ($data.StemmerDLLPathOverride) {
					$dll = $data.StemmerDLLPathOverride
				}
				elseif ($data.WBDLLPathOverride) {
					$dll = $data.WBDLLPathOverride
				}

				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $dll, 'NLPDlls'), $true)) {
					continue
				}

				$detection = [PSCustomObject]@{
					Name      = 'DLL Override on Natural Language Development Platform'
					Risk      = [TrawlerRiskPriority]::High
					Source    = 'Registry'
					Technique = "T1112: Modify Registry"
					Meta      = "Registry Path: " + $item.Name + ", DLL: " + $dll
				}
				$State.WriteDetection($detection)
			}
		}
	}
}

function Test-PrintMonitorDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking PrintMonitor DLLs")
	$standard_print_monitors = @(
		"APMon.dll",
		"AppMon.dll",
		"FXSMON.dll",
		"localspl.dll",
		"tcpmon.dll",
		"usbmon.dll",
		"WSDMon.dll" # Server 2016
	)
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Print\Monitors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.Driver) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.Driver, 'PrintMonitors'), $true)) {
					continue
				}

				if ($data.Driver -notin $standard_print_monitors) {
					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Print Monitor DLL'
						Risk      = [TrawlerRiskPriority]::Medium
						Source    = 'Registry'
						Technique = "T1112: Modify Registry"
						Meta      = "Registry Path: " + $item.Name + ", System32 DLL: " + $data.Driver
					}
					$State.WriteDetection($detection)
				}
			}
		}
	}
}

function Test-MicrosoftTelemetryCommands {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)

	$State.WriteMessage("Checking Microsoft TelemetryController")
	# Microsoft Telemetry Commands
	$allowed_telemetry_commands = @(
		"$env:systemroot\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun"
		"$env:systemroot\system32\CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun"
		"$env:systemroot\system32\CompatTelRunner.exe -m:appraiser.dll -f:UpdateAvStatus"
		"$env:systemroot\system32\CompatTelRunner.exe -m:devinv.dll -f:CreateDeviceInventory"
		"$env:systemroot\system32\CompatTelRunner.exe -m:pcasvc.dll -f:QueryEncapsulationSettings"
		"$env:systemroot\system32\CompatTelRunner.exe -m:invagent.dll -f:RunUpdate"
		"$env:systemroot\Windows\system32\CompatTelRunner.exe -m:generaltel.dll -f:DoCensusRun"

	)
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController"
	if (-not (Test-Path -Path $path)) {
		return 
	}

	foreach ($item in Get-TrawlerChildItem -Path $path) {
		$path = $State.PathAsRegistry($item.Name)
		$data = Get-TrawlerItemProperty -Path $path

		if ($data.Command -and $data.Command -notin $allowed_telemetry_commands) {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.Command, 'TelemetryCommands'), $true)) {
				continue
			}

			$State.WriteDetection([TrawlerDetection]::new(
					'Non-Standard Microsoft Telemetry Command',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1112: Modify Registry",
					[PSCustomObject]@{
						RegistryPath = $item.Name
						Command      = $data.Command
					}
				))
		}
	}
}

function Test-RemoteUACSetting {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking RemoteUAC Setting")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	if (-not (Test-Path -Path $path)) {
		return 
	}
	
	Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
		if ($_.Name -eq 'LocalAccountTokenFilterPolicy') {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'RemoteUAC'), $true)) {
				continue
			}

			if ($_.Value -eq 1) {
				$State.WriteDetection([TrawlerDetection]::new(
						'UAC Disabled for Remote Sessions',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1112: Modify Registry",
						[PSCustomObject]@{
							KeyLocation = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
							EntryName   = $_.Name
							EntryValue  = $_.Value
						}
					))
			}
		}
	}
}