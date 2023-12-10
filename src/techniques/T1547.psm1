function Test-T1547 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-LSA $State
	Test-TimeProviderDLLs $State
	Test-WinlogonHelperDLLs $State
	Test-LNK $State
	Test-PrintProcessorDLLs $State
	Test-ActiveSetup $State
}

<#
# Start T1547.002
#>

function Test-LSA {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking LSA DLLs")
	# LSA Security Package Review
	# TODO - Check DLL Modification/Creation times
	$common_ssp_dlls = @(
		"cloudAP", # Server 2016
		"ctxauth", #citrix
		"efslsaext.dll"
		"kerberos",
		"livessp",
		"lsasrv.dll"
		"msoidssp",
		"msv1_0",
		"negoexts",
		"pku2u",
		"schannel",
		"tspkg", # Server 2016
		"wdigest" # Server 2016
		"wsauth",
		"wsauth" #vmware
	)
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Control\Lsa"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot($_.Name, $package, 'LSASecurity')) {
							continue
						}

						$detection = [TrawlerDetection]::new(
							'LSA Security Package Review',
							[TrawlerRiskPriority]::Medium,
							'Registry',
							"T1547.005: Boot or Logon Autostart Execution: Security Support Provider",
							[PSCustomObject]@{
								KeyLocation = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
								EntryName   = $_.Name
								EntryValue  = $_.Value
							}
						)
						$State.WriteDetection($detection)
					}
				}
			}
			if ($_.Name -eq 'Authentication Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot($_.Name, $package, 'LSASecurity')) {
							continue
						}

						$detection = [TrawlerDetection]::new(
							'LSA Authentication Package Review',
							[TrawlerRiskPriority]::Medium,
							'Registry',
							"T1547.002: Boot or Logon Autostart Execution: Authentication Packages",
							[PSCustomObject]@{
								KeyLocation = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
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
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Control\Lsa\OSConfig"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot($_.Name, $package, 'LSASecurity')) {
							continue
						}

						$detection = [TrawlerDetection]::new(
							'LSA Security Package Review',
							[TrawlerRiskPriority]::Medium,
							'Registry',
							"T1547.005: Boot or Logon Autostart Execution: Security Support Provider",
							[PSCustomObject]@{
								KeyLocation = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
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
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Control\LsaExtensionConfig\LsaSrv"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Extensions' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot($_.Name, $package, 'LSASecurity')) {
							continue
						}

						$detection = [TrawlerDetection]::new(
							'LSA Extensions Review',
							[TrawlerRiskPriority]::Medium,
							'Registry',
							"T1547.005: Boot or Logon Autostart Execution: Security Support Provider",
							[PSCustomObject]@{
								KeyLocation = $path
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

	# T1556.002: Modify Authentication Process: Password Filter DLL
	# TODO - Check DLL Modification/Creation times
	$standard_lsa_notification_packages = @(
		"rassfm", # Windows Server 2019 AWS Lightsail
		"scecli" # Windows 10/Server
	)
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Control\Lsa"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "Notification Packages") {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $standard_lsa_notification_packages) {
						if ($State.IsExemptBySnapShot($_.Name, $package, 'LSASecurity')) {
							continue
						}

						$detection = [TrawlerDetection]::new(
							'Potential Exploitation via Password Filter DLL',
							[TrawlerRiskPriority]::High,
							'Registry',
							"T1556.002: Modify Authentication Process: Password Filter DLL",
							[PSCustomObject]@{
								KeyLocation = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
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
}

<#
# Start T1547.003
#>

function Test-TimeProviderDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Time Provider DLLs")
	$standard_timeprovider_dll = @(
		"$env:homedrive\Windows\System32\w32time.dll",
		"$env:homedrive\Windows\System32\vmictimeprovider.dll"
	)
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Services\W32Time\TimeProviders"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.DllName) {
				if ($standard_timeprovider_dll -notcontains $data.DllName) {
					if ($State.IsExemptBySnapShot($item.Name, $data.DllName, 'TimeProviders')) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'Non-Standard Time Providers DLL',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1547.003: Boot or Logon Autostart Execution: Time Providers",
						[PSCustomObject]@{
							RegistryPath = $item.Name
							DLL          = $data.DllName
						}
					)
					$State.WriteDetection($detection)
					
				}
			}
		}
	}
}

<#
# Start T1547.004
#>

function Test-WinlogonHelperDLLs {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Winlogon Helper DLLs")
	$standard_winlogon_helper_dlls = @(
		"C:\Windows\System32\userinit.exe,"
		"explorer.exe"
		"sihost.exe"
		"ShellAppRuntime.exe"
		"mpnotify.exe"
	)
	$path = "Registry::$($State.Drives.Hklm)Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -in 'Userinit', 'Shell', 'ShellInfrastructure', 'ShellAppRuntime', 'MPNotify' -and $_.Value -notin $standard_winlogon_helper_dlls) {
				if ($State.IsExemptBySnapShot($_.Name, $_.Value, 'WinlogonHelpers')) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'Potential WinLogon Helper Persistence',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL",
					[PSCustomObject]@{
						KeyLocation = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				)
				$State.WriteDetection($detection)
			}
		}
	}
}

<#
# Start T1547.009
#>

function Test-LNK {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# TODO - Maybe, Snapshots
	# Supports Drive Retargeting
	$State.WriteMessage("Checking LNK Targets")
	$current_date = Get-Date
	$WScript = New-Object -ComObject WScript.Shell
	$profile_names = Get-ChildItem "$($State.Drives.HomeDrive)\Users" -Attributes Directory | Select-Object *
	foreach ($user in $profile_names) {
		$path = "$($State.Drives.HomeDrive)\Users\" + $user.Name + "\AppData\Roaming\Microsoft\Windows\Recent"
		$items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".lnk" } | Select-Object *
		foreach ($item in $items) {
			#Write-Host $item.FullName, $item.LastWriteTime
			$lnk_target = $WScript.CreateShortcut($item.FullName).TargetPath
			$date_diff = $current_date - $item.LastWriteTime
			$comparison_timespan = New-TimeSpan -Days 90
			#Write-Host $date_diff.ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
			$date_diff_temp = $comparison_timespan - $date_diff
			if ($date_diff_temp -ge 0) {
				# If the LNK was modified within the last 90 days
				if ($lnk_target -match ".*\.exe.*\.exe.*") {
					$detection = [TrawlerDetection]::new(
						'LNK Target contains multiple executables',
						[TrawlerRiskPriority]::High,
						'LNK',
						"T1547.009: Boot or Logon Autostart Execution: Shortcut Modification",
						[PSCustomObject]@{
							LNKFile       = $item.FullName
							LNKTarget     = $lnk_target
							LastWriteTime = $item.LastWriteTime
						}
					)
					$State.WriteDetection($detection)
				}
				if (Test-SuspiciousTerms -Value $lnk_target) {
					$detection = [TrawlerDetection]::new(
						'LNK Target contains suspicious key-term',
						[TrawlerRiskPriority]::High,
						'LNK',
						"T1547.009: Boot or Logon Autostart Execution: Shortcut Modification",
						[PSCustomObject]@{
							LNKFile       = $item.FullName
							LNKTarget     = $lnk_target
							LastWriteTime = $item.LastWriteTime
						}
					)
					$State.WriteDetection($detection)
				}
				if ($lnk_target -match ".*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*") {
					$detection = [TrawlerDetection]::new(
						'LNK Target contains multiple file extensions',
						[TrawlerRiskPriority]::Medium,
						'LNK',
						"T1547.009: Boot or Logon Autostart Execution: Shortcut Modification",
						[PSCustomObject]@{
							LNKFile       = $item.FullName
							LNKTarget     = $lnk_target
							LastWriteTime = $item.LastWriteTime
						}
					)
					$State.WriteDetection($detection)
				}

			}
		}
	}
}

<#
# Start T1547.0012
#>

function Test-PrintProcessorDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking PrintProcessor DLLs")
	$standard_print_processors = @(
		"winprint.dll"
	)
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Control\Print\Environments\Windows x64\Print Processors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.Driver) {
				if ($standard_print_processors -notcontains $data.Driver) {
					if ($State.IsExemptBySnapShot($item.Name, $data.Driver, 'PrintProcessors')) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'Non-Standard Print Processor DLL',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1547.012: Boot or Logon Autostart Execution: Print Processors",
						[PSCustomObject]@{
							RegistryPath = $item.Name
							DLL          = $data.Driver
						}
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Control\Print\Environments\Windows x64\Print Processors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.Driver) {
				if ($standard_print_processors -notcontains $data.Driver) {
					if ($State.IsExemptBySnapShot($item.Name, $data.Driver, 'PrintProcessors')) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'Non-Standard Print Processor DLL',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1547.012: Boot or Logon Autostart Execution: Print Processors",
						[PSCustomObject]@{
							RegistryPath = $item.Name
							DLL          = $data.Driver
						}
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
}

<#
# Start T1547.014
#>

function Test-ActiveSetup {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Active Setup Stubs")
	# T1547.014 - Boot or Logon Autostart Execution: Active Setup
	$standard_stubpaths = @(
		"/UserInstall",
		'"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', # Server 2016
		"$($State.Drives.AssumedHomeDrive)\Windows\System32\ie4uinit.exe -UserConfig", # 10
		"$($State.Drives.AssumedHomeDrive)\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install", # 10
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', # Server 2019
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', # Server 2019
		"$($State.Drives.AssumedHomeDrive)\Windows\System32\unregmp2.exe /FirstLogon", # 10
		"$($State.Drives.AssumedHomeDrive)\Windows\System32\unregmp2.exe /ShowWMP", # 10
		"$($State.Drives.AssumedHomeDrive)\Windows\System32\ie4uinit.exe -EnableTLS",
		"$($State.Drives.AssumedHomeDrive)\Windows\System32\ie4uinit.exe -DisableSSL3"
		"U"
		"regsvr32.exe /s /n /i:U shell32.dll"
		"$($State.Drives.AssumedHomeDrive)\Windows\system32\regsvr32.exe /s /n /i:/UserInstall C:\Windows\system32\themeui.dll"
		"$($State.Drives.AssumedHomeDrive)\Windows\system32\unregmp2.exe /FirstLogon /Shortcuts /RegBrowsers /ResetMUI"
	)
	$path = "Registry::$($State.Drives.Hklm)SOFTWARE\Microsoft\Active Setup\Installed Components"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.StubPath) {
				if ($standard_stubpaths -notcontains $data.StubPath -and $data.StubPath -notmatch ".*(\\Program Files\\Google\\Chrome\\Application\\.*chrmstp.exe|Microsoft\\Edge\\Application\\.*\\Installer\\setup.exe).*") {
					if ($State.IsExemptBySnapShot($item.Name, $data.StubPath, 'ActiveSetup')) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'Non-Standard StubPath Executed on User Logon',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1547.014: Boot or Logon Autostart Execution: Active Setup",
						[PSCustomObject]@{
							RegistryPath = $item.Name
							StubPath     = $data.StubPath
						}
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
}