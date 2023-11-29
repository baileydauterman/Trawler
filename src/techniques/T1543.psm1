function Test-T1543 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-Services $State
	Test-ServicesByRegex $State
}

function Test-Services {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Support Drive Retargeting
	$State.WriteMessage("Checking Windows Services")

	#$services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
	$service_path = "$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Services"
	$service_list = New-Object -TypeName "System.Collections.ArrayList"

	if (-not (Test-Path -Path "Registry::$service_path")) {
		return
	}
	
	foreach ($item in Get-TrawlerItemData -Path $service_path -AsRegistry -ItemType ChildItem) {
		$data = Get-TrawlerItemData -Path $item.Name -AsRegistry -ItemType ItemProperty

		if ($data.ImagePath) {
			$service = [PSCustomObject]@{
				Name     = $data.PSChildName
				PathName = $data.ImagePath
			}
			$service.PathName = $service.PathName.Replace("\SystemRoot", "$($State.Drives.AssumedHomeDrive)\Windows")
			$service_list.Add($service) | Out-Null
		}
	}

	foreach ($service in $service_list) {
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($service.Name, $service.PathName, "Services"), $true)) {
			continue
		}

		if (Test-RemoteAccessTrojanTerms -Value $service.PathName) {
			# Service has a suspicious launch pattern matching a known RAT
			$detection = [TrawlerDetection]::new(
				'Service Argument has known-RAT Keyword',
				[TrawlerRiskPriority]::Medium,
				'Services',
				"T1543.003: Create or Modify System Process: Windows Service",
				[PSCustomObject]@{
					ServiceName = $service.Name
					ServicePath = $service.PathName
					RATKeyword  = $term
				}
			)
			$State.WriteDetection($detection)
		}
			
		if ($service.PathName -match "$($State.Drives.AssumedHomeDrive)\\Windows\\Temp\\.*") {
			# Service launching from Windows\Temp
			$detection = [TrawlerDetection]::new(
				'Service Launching from Windows Temp Directory',
				[TrawlerRiskPriority]::High,
				'Services',
				"T1543.003: Create or Modify System Process: Windows Service",
				[PSCustomObject]@{
					ServiceName = $service.Name
					ServicePath = $service.PathName
				}
			)
			$State.WriteDetection($detection)
		}

		# Detection - Non-Standard Tasks
		foreach ($i in Build-ServiceExePaths -State $State) {
			if ( $service.PathName -like $i) {
				$exe_match = $true
				break
			}
			elseif ($service.PathName.Length -gt 0) {
				$exe_match = $false
			}
		}

		if ($exe_match -eq $false) {
			# Current Task Executable Path is non-standard
			$detection = [TrawlerDetection]::new(
				'Non-Standard Service Path',
				[TrawlerRiskPriority]::Low,
				'Services',
				"T1543.003: Create or Modify System Process: Windows Service",
				[PSCustomObject]@{
					ServiceName = $service.Name
					ServicePath = $service.PathName
				}
			)
			$State.WriteDetection($detection)
		}

		if ($service.PathName -match ".*cmd.exe /(k|c).*") {
			# Service has a suspicious launch pattern
			$detection = [TrawlerDetection]::new(
				'Service launching from cmd.exe',
				[TrawlerRiskPriority]::Medium,
				'Services',
				"T1543.003: Create or Modify System Process: Windows Service",
				[PSCustomObject]@{
					ServiceName = $service.Name
					ServicePath = $service.PathName
				}
			)
			$State.WriteDetection($detection)
		}

		if ($service.PathName -match ".*powershell.exe.*") {
			# Service has a suspicious launch pattern
			$detection = [TrawlerDetection]::new(
				'Service launching from powershell.exe',
				[TrawlerRiskPriority]::Medium,
				'Services',
				"T1543.003: Create or Modify System Process: Windows Service",
				[PSCustomObject]@{
					ServiceName = $service.Name
					ServicePath = $service.PathName
				}
			)
			$State.WriteDetection($detection)
		}

		if (Test-SuspiciousTerms $service.PathName) {
			# Service has a suspicious launch pattern
			$detection = [TrawlerDetection]::new(
				'Service launching with suspicious keywords',
				[TrawlerRiskPriority]::High,
				'Services',
				"T1543.003: Create or Modify System Process: Windows Service",
				[PSCustomObject]@{
					ServiceName = $service.Name
					ServicePath = $service.PathName
				}
			)
			$State.WriteDetection($detection)
		}
	}
}

function Test-ServicesByRegex {
	# TODO - Check FailureCommand for abnormal entries
	# Supports Drive Retargeting
	# Support Dynamic Snapshotting
	$State.WriteMessage("Checking Service Registry Entries")
	# Service DLL Inspection

	$path = "{0}SYSTEM\$($State.Drives.CurrentControlSet)\Services" -f $($State.Drives.Hklm)
	if (-not (Test-Path -Path "Registry::$path")) {
		return
	}

	foreach ($service in Get-TrawlerItemData -Path $path -AsRegistry -ItemType ChildItem) {
		foreach ($item in Get-TrawlerItemData -Path $service.Name -ItemType ItemProperty -AsRegistry) {
			if ($item.Name -ne 'ImagePath') {
				continue 
			}

			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($service.Name, $item.Value, 'Services_REG'), $true)) {
				continue
			}

			if ($image_path_lookup.ContainsKey($service.Name) -and $item.Value -notmatch $image_path_lookup[$service.Name]) {
				$detection = [TrawlerDetection]::new(
					'Possible Service Hijack - Unexpected ImagePath Location',
					[TrawlerRiskPriority]::Medium,
					'Services',
					"T1543.003: Create or Modify System Process: Windows Service",
					[PSCustomObject]@{
						Key                   = $service.Name
						Value                 = $item.Value
						RegexExpectedLocation = $image_path_lookup[$service.Name]
					}
				)

				$State.WriteDetection($detection)
			}
		}

		foreach ($child_key in Get-TrawlerChildItem -Path $service.Name -AsRegistry) {
			foreach ($item in Get-TrawlerItemData -Path $child_key.Name -ItemType ItemProperty -AsRegistry) {
				if ($item.Name -ne "ServiceDll") {
					continue 
				}

				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($child_key.Name, $item.Value, 'Services_REG'), $true)) {
					continue
				}

				if ($service_dll_lookup.ContainsKey($child_key.Name) -and $item.Value -notmatch $service_dll_lookup[$child_key.Name]) {
					$detection = [TrawlerDetection]::new(
						'Possible Service Hijack - Unexpected ServiceDll Location',
						[TrawlerRiskPriority]::Medium,
						'Services',
						"T1543.003: Create or Modify System Process: Windows Service",
						[PSCustomObject]@{
							Key                   = $child_key.Name
							Value                 = $item.Value
							RegexExpectedLocation = $service_dll_lookup[$child_key.Name]
						}
					)

					$State.WriteDetection($detection)
				}
			}
		}
	}
}