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
		[TrawlerState]
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
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Lsa"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $package, 'LSASecurity'), $true)) {
							continue
						}

						$detection = [PSCustomObject]@{
							Name      = 'LSA Security Package Review'
							Risk      = [TrawlerRiskPriority]::Medium
							Source    = 'Registry'
							Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						$State.WriteDetection($detection)
					}
				}
			}
			if ($_.Name -eq 'Authentication Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $package, 'LSASecurity'), $true)) {
							continue
						}

						$detection = [PSCustomObject]@{
							Name      = 'LSA Authentication Package Review'
							Risk      = [TrawlerRiskPriority]::Medium
							Source    = 'Registry'
							Technique = "T1547.002: Boot or Logon Autostart Execution: Authentication Packages"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						$State.WriteDetection($detection)
					}
				}
			}
		}
	}
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Lsa\OSConfig"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $package, 'LSASecurity'), $true)) {
							continue
						}

						$detection = [PSCustomObject]@{
							Name      = 'LSA Security Package Review'
							Risk      = [TrawlerRiskPriority]::Medium
							Source    = 'Registry'
							Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						$State.WriteDetection($detection)
					}
				}
			}
		}
	}
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\LsaExtensionConfig\LsaSrv"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Extensions' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $package, 'LSASecurity'), $true)) {
							continue
						}

						$detection = [PSCustomObject]@{
							Name      = 'LSA Extensions Review'
							Risk      = [TrawlerRiskPriority]::Medium
							Source    = 'Registry'
							Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
							Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
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
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Lsa"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "Notification Packages") {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $standard_lsa_notification_packages) {
						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $package, 'LSASecurity'), $true)) {
							continue
						}

						$detection = [PSCustomObject]@{
							Name      = 'Potential Exploitation via Password Filter DLL'
							Risk      = [TrawlerRiskPriority]::High
							Source    = 'Registry'
							Technique = "T1556.002: Modify Authentication Process: Password Filter DLL"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
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
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Time Provider DLLs")
	$standard_timeprovider_dll = @(
		"$env:homedrive\Windows\System32\w32time.dll",
		"$env:homedrive\Windows\System32\vmictimeprovider.dll"
	)
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Services\W32Time\TimeProviders"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.DllName) {
				if ($standard_timeprovider_dll -notcontains $data.DllName) {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.DllName, 'TimeProviders'), $true)) {
						continue
					}

					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Time Providers DLL'
						Risk      = [TrawlerRiskPriority]::High
						Source    = 'Registry'
						Technique = "T1547.003: Boot or Logon Autostart Execution: Time Providers"
						Meta      = "Registry Path: " + $item.Name + ", DLL: " + $data.DllName
					}
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
	$path = "Registry::$($State.DriveTargets.Hklm)Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -in 'Userinit', 'Shell', 'ShellInfrastructure', 'ShellAppRuntime', 'MPNotify' -and $_.Value -notin $standard_winlogon_helper_dlls) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'WinlogonHelpers'), $true)) {
					continue
				}

				$detection = [PSCustomObject]@{
					Name      = 'Potential WinLogon Helper Persistence'
					Risk      = [TrawlerRiskPriority]::High
					Source    = 'Registry'
					Technique = "T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL"
					Meta      = "Key Location: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
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
		[TrawlerState]
		$State
	)
	# TODO - Maybe, Snapshots
	# Supports Drive Retargeting
	$State.WriteMessage("Checking LNK Targets")
	$current_date = Get-Date
	$WScript = New-Object -ComObject WScript.Shell
	$profile_names = Get-ChildItem "$($State.DriveTargets.HomeDrive)\Users" -Attributes Directory | Select-Object *
	foreach ($user in $profile_names) {
		$path = "$($State.DriveTargets.HomeDrive)\Users\" + $user.Name + "\AppData\Roaming\Microsoft\Windows\Recent"
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
					$detection = [PSCustomObject]@{
						Name      = 'LNK Target contains multiple executables'
						Risk      = [TrawlerRiskPriority]::High
						Source    = 'LNK'
						Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
						Meta      = "LNK File: " + $item.FullName + ", LNK Target: " + $lnk_target + ", Last Write Time: " + $item.LastWriteTime
					}
					$State.WriteDetection($detection)
				}
				if (Test-SuspiciousTerms -Value $lnk_target) {
					$detection = [PSCustomObject]@{
						Name      = 'LNK Target contains suspicious key-term'
						Risk      = [TrawlerRiskPriority]::High
						Source    = 'LNK'
						Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
						Meta      = "LNK File: " + $item.FullName + ", LNK Target: " + $lnk_target + ", Last Write Time: " + $item.LastWriteTime
					}
					$State.WriteDetection($detection)
				}
				if ($lnk_target -match ".*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*") {
					$detection = [PSCustomObject]@{
						Name      = 'LNK Target contains multiple file extensions'
						Risk      = [TrawlerRiskPriority]::Medium
						Source    = 'LNK'
						Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
						Meta      = "LNK File: " + $item.FullName + ", LNK Target: " + $lnk_target + ", Last Write Time: " + $item.LastWriteTime
					}
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
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking PrintProcessor DLLs")
	$standard_print_processors = @(
		"winprint.dll"
	)
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Print\Environments\Windows x64\Print Processors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.Driver) {
				if ($standard_print_processors -notcontains $data.Driver) {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.Driver, 'PrintProcessors'), $true)) {
						continue
					}

					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Print Processor DLL'
						Risk      = [TrawlerRiskPriority]::High
						Source    = 'Registry'
						Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
						Meta      = "Registry Path: " + $item.Name + ", DLL: " + $data.Driver
					}
					$State.WriteDetection($detection)
				}
			}
		}
	}
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Print\Environments\Windows x64\Print Processors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.Driver) {
				if ($standard_print_processors -notcontains $data.Driver) {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.Driver, 'PrintProcessors'), $true)) {
						continue
					}

					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Print Processor DLL'
						Risk      = [TrawlerRiskPriority]::High
						Source    = 'Registry'
						Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
						Meta      = "Registry Path: " + $item.Name + ", DLL: " + $data.Driver
					}
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
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Active Setup Stubs")
	# T1547.014 - Boot or Logon Autostart Execution: Active Setup
	$standard_stubpaths = @(
		"/UserInstall",
		'"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', # Server 2016
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\ie4uinit.exe -UserConfig", # 10
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install", # 10
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', # Server 2019
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', # Server 2019
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\unregmp2.exe /FirstLogon", # 10
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\unregmp2.exe /ShowWMP", # 10
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\ie4uinit.exe -EnableTLS",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\ie4uinit.exe -DisableSSL3"
		"U"
		"regsvr32.exe /s /n /i:U shell32.dll"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\regsvr32.exe /s /n /i:/UserInstall C:\Windows\system32\themeui.dll"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\unregmp2.exe /FirstLogon /Shortcuts /RegBrowsers /ResetMUI"
	)
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Active Setup\Installed Components"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty -Path $path
			if ($data.StubPath) {
				if ($standard_stubpaths -notcontains $data.StubPath -and $data.StubPath -notmatch ".*(\\Program Files\\Google\\Chrome\\Application\\.*chrmstp.exe|Microsoft\\Edge\\Application\\.*\\Installer\\setup.exe).*") {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.StubPath, 'ActiveSetup'), $true)) {
						continue
					}

					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard StubPath Executed on User Logon'
						Risk      = [TrawlerRiskPriority]::High
						Source    = 'Registry'
						Technique = "T1547.014: Boot or Logon Autostart Execution: Active Setup"
						Meta      = "Registry Path: " + $item.Name + ", StubPath: " + $data.StubPath
					}
					$State.WriteDetection($detection)
				}
			}
		}
	}
}