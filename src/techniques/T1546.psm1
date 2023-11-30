function Test-T1546 {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	Test-AppPaths $State
	Test-CommandAutoRunProcessors $State
	Test-ContextMenu $State
	Test-DiskCleanupHandlers $State
	Test-DebuggerHijacks $State
	Test-DisableLowILProcessIsolation $State
	Test-Narrator $State
	Test-NotepadPlusPlusPlugins $State
	Test-OfficeAI $State
	Test-UninstallStrings $State
	Test-PolicyManager $State
	Test-WindowsLoadKey $State
	Test-AutoDialDLL $State
	Test-HTMLHelpDLL $State
	Test-AssociationHijack $State
	Test-ScreenSaverEXE $State
	Test-WMIConsumers $State
	Test-NetSHDLLs $State
	Test-KnownHijacks $State
	Test-ModifiedWindowsAccessibilityFeature $State
	Test-AppCertDLLs $State
	Test-AppInitDLLs $State
	Test-ApplicationShims $State
	Test-IFEO $State
	Test-RegistryChecks $State
	Test-SilentProcessExitMonitoring $State
	Test-PowerShellProfiles $State
	Test-WellKnownCOM $State
	Test-ComHijacks $State
	Test-FolderOpen $State
}

function Test-AppPaths {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking AppPaths")
	$path = "$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"

	if (-not (Test-TrawlerPath -Path $path -AsRegistry)) {
		return
	}

	foreach ($item in Get-TrawlerChildItem -Path $path -AsRegistry) {
		Get-TrawlerItemData -Path $item.Name -ItemType ItemProperty -AsRegistry | ForEach-Object {
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

			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $_.Value, 'AppPaths'))) {
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

function Test-CommandAutoRunProcessors {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	
	$State.WriteMessage("Checking Command AutoRun Processors")
	$path = "Registry::$($State.Drives.Hklm)`SOFTWARE\Microsoft\Command Processor"

	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -ne 'AutoRun' -or $State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'CommandAutorunProcessor'))) {
				continue
			}
			
			$State.WriteDetection([TrawlerDetection]::new(
					'Potential Hijacking of Command AutoRun Processor',
					[TrawlerRiskPriority]::VeryHigh,
					'Registry',
					"T1546: Event Triggered Execution",
					[PSCustomObject]@{
						KeyLocation = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor'
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				))
		}
	}

	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Command Processor"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (-not (Test-Path -Path $path)) {
			continue 
		}

		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -ne 'AutoRun' -or $State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'CommandAutorunProcessor'))) {
				continue
			}
			
			$State.WriteDetection([TrawlerDetection]::new(
					'Potential Hijacking of Command AutoRun Processor',
					[TrawlerRiskPriority]::VeryHigh,
					'Registry',
					"T1546: Event Triggered Execution",
					[PSCustomObject]@{
						KeyLocation = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor'
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				))
		}
	}
}

function Test-ContextMenu {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}
	# HKEY_USERS\S-1-5-21-63485881-451500365-4075260605-1001\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}
	# The general idea is that {B7CDF620-DB73-44C0-8611-832B261A0107} represents the Explorer context menu - we are scanning ALL ContextMenuHandlers for DLLs present in the (Default) property as opposed to a CLSID
	# https://ristbs.github.io/2023/02/15/hijack-explorer-context-menu-for-persistence-and-fun.html
	# Supports Drive Retargeting
	# No Snapshotting right now - can add though.
	# TODO - Check ColumnHandlers, CopyHookHandlers, DragDropHandlers and PropertySheetHandlers in same key, HKLM\Software\Classes\*\shellex
	$State.WriteMessage("Checking Context Menu Handlers")

	$path = "$($State.Drives.Hklm)SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
	if ($State.TestPathAsRegistry($path)) {
		foreach ($item in Get-TrawlerChildItem $path -AsRegistry) {
			Get-TrawlerItemData -Path $item.Name -ItemType ItemProperty -AsRegistry | ForEach-Object {
				if ($_.Name -eq '(Default)' -and $_.Value -match ".*\.dll.*") {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $_.Value, 'ContextMenuHandlers'))) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'DLL loaded in ContextMenuHandler',
						[TrawlerRiskPriority]::Medium,
						'Windows Context Menu',
						"T1546: Event Triggered Execution",
						"Key: " + $item.Name + ", DLL: " + $_.Value
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}

	$basepath = "{0}\SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath -f $p

		if (-not $State.TestPathAsRegistry($path)) {
			continue 
		}

		foreach ($item in Get-TrawlerChildItem $path -AsRegistry) {
			Get-TrawlerItemData -Path $item.Name -ItemType ItemProperty -AsRegistry | ForEach-Object {
				if ($_.Name -eq '(Default)' -and $_.Value -match ".*\.dll.*") {
					$detection = [TrawlerDetection]::new(
						'DLL loaded in ContextMenuHandler',
						[TrawlerRiskPriority]::Medium,
						'Windows Context Menu',
						"T1546: Event Triggered Execution",
						"Key: " + $item.Name + ", DLL: " + $_.Value
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
}

function Test-DiskCleanupHandlers {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Retargeting/Snapshot
	$State.WriteMessage("Checking DiskCleanupHandlers")
	$default_cleanup_handlers = @(
		"C:\Windows\System32\DATACLEN.DLL",
		"C:\Windows\System32\PeerDistCleaner.dll",
		"C:\Windows\System32\D3DSCache.dll",
		"C:\Windows\system32\domgmt.dll",
		"C:\Windows\System32\pnpclean.dll",
		"C:\Windows\System32\occache.dll",
		"C:\Windows\System32\ieframe.dll",
		"C:\Windows\System32\LanguagePackDiskCleanup.dll",
		"C:\Windows\system32\setupcln.dll",
		"C:\Windows\system32\shell32.dll",
		"C:\Windows\system32\wmp.dll",
		"C:\Windows\System32\thumbcache.dll",
		"C:\Windows\system32\scavengeui.dll",
		"C:\Windows\System32\fhcleanup.dll"
	)
	$path = "$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
	if (Test-Path -LiteralPath "Registry::$path") {
		$items = Get-TrawlerChildItem "Registry::$path"
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty $path
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(Default)') {
					$target_prog = ''
					$tmp_path = "$($State.Drive.Hkcr)CLSID\$($_.Value)\InProcServer32"
					if (Test-Path -LiteralPath "Registry::$tmp_path") {
						$data_tmp = Get-TrawlerItemProperty "Registry::$tmp_path"
						$data_tmp.PSObject.Properties | ForEach-Object {
							if ($_.Name -eq '(Default)') {
								$target_prog = $_.Value
							}
						}
					}
					if ($target_prog -in $default_cleanup_handlers) {
						continue
					}
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $target_prog, 'DiskCleanupHandlers'))) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'Non-Default DiskCleanupHandler Program',
						[TrawlerRiskPriority]::Low,
						'Registry',
						"T1546: Event Triggered Execution",
						"Key: " + $item.Name + ", Program: " + $target_prog
					)
					$State.WriteDetection($detection)
				}
				
			}
		}
	}
}

function Test-DebuggerHijacks {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	$State.WriteMessage("Checking Debuggers")
	# TODO - Rearrange this code to use an array of paths and key names
	# allowtable_debuggers
	# Debugger Hijacks
	# AeDebug 32
	$knownPaths = @(
		"{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"	
		"{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebugProtected"
		"{0}SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"
		"{0}SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebugProtected"
		"{0}SOFTWARE\Microsoft\.NETFramework"
		"{0}SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
		"{0}SOFTWARE\Classes\CLSID\{834128A2-51F4-11D0-8F20-00805F2CD064}\LocalServer32"
		"{0}SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs"
		"{0}SOFTWARE\Classes\CLSID\{78A51822-51F4-11D0-8F20-00805F2CD064}\InprocServer32"
	)

	foreach ($path in $knownPaths) {
		$path = $path -f $State.Drives.Hklm

		if (-not $State.TestPathAsRegistry($path)) {
			continue
		}

		Get-TrawlerItemData -Path $path -ItemType ItemProperty -AsRegistry | ForEach-Object {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($path, $_.Value, 'Debuggers'))) {
				continue
			}

			$match = $false
			if ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p") {
				$match = $true
			}
			elseif ($_.Name -eq 'ProtectedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $match -eq $false) {
				$match = $true
			}
			elseif ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $match -eq $false) {
				$match = $true
			}
			elseif ($_.Name -eq 'ProtectedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $match -eq $false) {
				$match = $true
			}
			elseif ($_.Name -eq 'DbgManagedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" PID %d APPDOM %d EXTEXT `"%s`" EVTHDL %d" -and $match -eq $false) {
				$match = $true
			}
			elseif ($_.Name -eq '@' -and ($_.Value -ne "`"$env:homedrive\Program Files(x86)\Microsoft Script Debugger\msscrdbg.exe`"" -or $_.Value -ne "`"$env:homedrive\Program Files\Microsoft Script Debugger\msscrdbg.exe`"") -and $match -eq $false) {
				$match = $true
			}
			elseif (($_.Name -in '(default)' -and $match -eq $false -and $_.Value -ne "$($State.Drives.AssumedHomeDrive)\Program Files\Common Files\Microsoft Shared\VS7Debug\pdm.dll") -or ($_.Name -eq '@' -and $_.Value -ne "`"$($State.Drives.AssumedHomeDrive)\WINDOWS\system32\pdm.dll`"")) {
				$match = $true
			}
			elseif ($_.Name -in 'Debugger', 'ReflectDebugger') {
				$match = $true
			}

			if ($match) {
				$State.WriteDetection([TrawlerDetection]::new(
						'Potential AeDebug Hijacking',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1546: Event Triggered Execution",
						"Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					))
			}
		}
	}

	$basepath = "{0}\CLSID\{834128A2-51F4-11D0-8F20-00805F2CD064}\LocalServer32"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath -f $p
		if (-not $State.TestPathAsRegistry($path)) {
			continue
		}
		
		Get-TrawlerItemData -Path $path -ItemType ItemProperty -AsRegistry | ForEach-Object {
			if ($_.Name -eq '@' -and ($_.Value -ne "`"$($State.Drives.AssumedHomeDrive)\Program Files(x86)\Microsoft Script Debugger\msscrdbg.exe`"" -or $_.Value -ne "`"$($State.Drives.AssumedHomeDrive)\Program Files\Microsoft Script Debugger\msscrdbg.exe`"")) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($path, $_.Value, 'Debuggers'))) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'Potential Microsoft Script Debugger Hijacking',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1546: Event Triggered Execution",
					"Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				)
				$State.WriteDetection($detection)
			}
		}
	}
}


function Test-DisableLowILProcessIsolation {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	# Supports Drive Retargeting
	# Supports Snapshotting
	$State.WriteMessage("Checking for COM Objects running without Low Integrity Isolation")

	$path = "$($State.Drives.Hklm)Software\Classes\CLSID"
	$allowlist = @(
		"@C:\\Program Files\\Microsoft Office\\Root\\VFS\\ProgramFilesCommonX64\\Microsoft Shared\\Office16\\oregres\.dll.*"
		"@wmploc\.dll.*"
		"@C:\\Windows\\system32\\mssvp\.dll.*"
		"@C:\\Program Files\\Common Files\\System\\wab32res\.dll.*"
	)

	if (-not ($State.TestPathAsRegistry($path))) {
		return
	}

	foreach ($item in Get-TrawlerChildItem $path -AsRegistry) {
		Get-TrawlerItemData -Path $item.Name -ItemType ItemProperty -AsRegistry | ForEach-Object {
			if ($_.Name -eq 'DisableLowILProcessIsolation' -and $_.Value -eq 1) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $item.Name, 'DisableLowIL'))) {
					continue
				}
					
				if ($data.DisplayName) {
					$displayname = $data.DisplayName
				}
				else {
					$displayname = ""
				}

				$pass = $false

				foreach ($allow in $allowlist) {
					if ($displayname -match $allow) {
						$pass = $true
						break
					}
				}

				if ($pass -eq $false) {
					$detection = [TrawlerDetection]::new(
						'COM Object Registered with flag disabling low-integrity process isolation',
						[TrawlerRiskPriority]::Medium,
						'Registry',
						"T1546: Event Triggered Execution",
						"Key: " + $item.Name + ", Display Name: " + $displayname
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
}

function Test-Narrator {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	
	# Supports Drive Retargeting
	# https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
	$State.WriteMessage("Checking Narrator MSTTSLocEnUS.dll Presence")
	$basepath = "$($State.Drives.HomeDrive)\Windows\System32\Speech\Engines\TTS\MSTTSLocEnUS.DLL"

	if (-not (Test-Path $basepath)) {
		return 
	}

	$item = Get-Item -Path $basepath -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime

	$detection = [TrawlerDetection]::new(
		'Narrator Missing DLL is Present',
		[TrawlerRiskPriority]::Medium,
		'Windows Narrator',
		"T1546: Event Triggered Execution",
			($item | Select-Object FullName, CreationTime, LastWriteTime)
	)

	$State.WriteDetection($detection)
}

function Test-NotepadPlusPlusPlugins {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Notepad++ Plugins")

	$basepaths = @(
		"{0}\Program Files\Notepad++\plugins"
		"{0}\Program Files (x86)\Notepad++\plugins"
	)

	$allowlisted = @(
		".*\\Config\\nppPluginList\.dll"
		".*\\mimeTools\\mimeTools\.dll"
		".*\\NppConverter\\NppConverter\.dll"
		".*\\NppExport\\NppExport\.dll"
	)

	foreach ($basepath in $basepaths) {
		$basepath = $basepath -f $State.Drives.HomeDrive
		if (-not (Test-Path $basepath)) {
			continue 
		}
		
		$dlls = Get-ChildItem -Path $basepath -File -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue

		foreach ($item in $dlls) {
			$match = $false

			foreach ($allow_match in $allowlisted) {
				if ($item.FullName -match $allow_match) {
					$match = $true
				}
			}

			if ($match -eq $false) {
				$detection = [TrawlerDetection]::new(
					'Non-Default Notepad++ Plugin DLL',
					[TrawlerRiskPriority]::Medium,
					'Notepad++',
					"T1546: Event Triggered Execution",
					($item | Select-Object FullName, CreationTime, LastWriteTime)
				)
				$State.WriteDetection($detection)
			}
		}
	}
}

function Test-OfficeAI {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Drive Retargeting
	# https://twitter.com/Laughing_Mantis/status/1645268114966470662
	$State.WriteMessage("Checking Office AI.exe Presence")
	$basepath = "$($State.Drives.HomeDrive)\Program Files\Microsoft Office\root\Office*"
	if (-not (Test-Path $basepath)) {
		return 
	}
	
	$path = "$($State.Drives.HomeDrive)\Program Files\Microsoft Office\root"
	foreach ($dir in Get-ChildItem -Path $path -Directory -Filter "Office*" -ErrorAction SilentlyContinue) {
		$ai = $dir.FullName + "\ai.exe"
		if (-not (Test-Path $ai)) {
			continue 
		}

		$item = Get-Item -Path $ai -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime

		$detection = [TrawlerDetection]::new(
			'AI.exe in Office Directory',
			[TrawlerRiskPriority]::Medium,
			'Windows Context Menu',
			"T1546: Event Triggered Execution",
			($item)
		)

		$State.WriteDetection($detection)
	}
}

function Test-UninstallStrings {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Uninstall Strings")
	$path = "Registry::$($State.Drives.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	if (-not (Test-Path -Path $path)) {
		return 
	}

	foreach ($item in Get-TrawlerChildItem -Path $path) {
		$data = Get-TrawlerItemProperty -Path $path -AsRegistry

		if ($data.UninstallString -and (Test-SuspiciousTerms -Value $data.UninstallString)) {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.UninstallString, 'UninstallString'))) {
				continue
			}

			$detection = [TrawlerDetection]::new(
				'Uninstall String with Suspicious Keywords',
				[TrawlerRiskPriority]::High,
				'Registry',
				"T1546: Event Triggered Execution",
				"Application: " + $item.Name + ", Uninstall String: " + $data.UninstallString
			)
			$State.WriteDetection($detection)
		}

		if ($data.QuietUninstallString -and (Test-SuspiciousTerms -Value $data.QuietUninstallString)) {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.QuietUninstallString, 'QuietUninstallString'))) {
				continue
			}

			$detection = [TrawlerDetection]::new(
				'Uninstall String with Suspicious Keywords',
				[TrawlerRiskPriority]::High,
				'Registry',
				"T1546: Event Triggered Execution",
				"Application: " + $item.Name + ", Uninstall String: " + $data.QuietUninstallString
			)
			$State.WriteDetection($detection)
		}
	}
}

function Test-PolicyManager {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking PolicyManager DLLs")
	$allow_listed_values = @(
		"%SYSTEMROOT%\system32\PolicyManagerPrecheck.dll"
		"%SYSTEMROOT%\system32\hascsp.dll"
	)
	$path = "Registry::$($State.Drives.Hklm)SOFTWARE\Microsoft\PolicyManager\default"
	if (Test-Path -Path $path) {
		foreach ($item in Get-TrawlerChildItem -Path $path) {
			$path = "Registry::" + $item.Name
			foreach ($subkey in Get-TrawlerChildItem -Path $path) {
				$subpath = "Registry::" + $subkey.Name
				$data = Get-TrawlerItemProperty -Path $subpath

				if ($data.PreCheckDLLPath) {
					if ($data.PreCheckDLLPath -notin $allow_listed_values) {
						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($subkey.Name, $data.PreCheckDLLPath, 'PolicyManagerPreCheck'))) {
							continue
						}

						$detection = [TrawlerDetection]::new(
							'Non-Standard Policy Manager DLL',
							[TrawlerRiskPriority]::High,
							'Registry',
							"T1546: Event Triggered Execution",
							"Path: " + $subkey.Name + ", Entry Name: PreCheckDLLPath, DLL: " + $data.PreCheckDLLPath
						)
						$State.WriteDetection($detection)
					}
				}

				if ($data.transportDllPath) {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($subkey.Name, $data.transportDllPath, 'PolicyManagerTransport'))) {
						continue
					}

					if ($pass -eq $false) {
						$detection = [TrawlerDetection]::new(
							'Non-Standard Policy Manager DLL',
							[TrawlerRiskPriority]::High,
							'Registry',
							"T1546: Event Triggered Execution",
							"Path: " + $subkey.Name + ", Entry Name: transportDllPath, DLL: " + $data.transportDllPath
						)
						$State.WriteDetection($detection)
					}
				}
			}

		}
	}
}

function Test-WindowsLoadKey {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# TODO - Add Snapshot Skipping
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Windows Load")
	$basepath = "{0}\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath -f $p
		if (-not (Test-Path -Path "Registry::$path")) {
			continue 
		}

		Get-TrawlerItemData -Path $path -ItemType ItemProperty -AsRegistry | ForEach-Object {
			if ($_.Name -in 'Load') {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'WindowsLoad'))) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'Potential Windows Load Hijacking',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1546: Event Triggered Execution",
					"Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				)
				$State.WriteDetection($detection)
			}
		}
	}
}

function Test-AutoDialDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	# Supports Drive Retargeting
	$State.WriteMessage("Checking Autodial DLL")
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\CurrentControlSet\Services\WinSock2\Parameters"

	if (-not (Test-Path -Path $path)) {
		return 
	}

	Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
		if ($_.Name -eq 'AutodialDLL' -and $_.Value -ne 'C:\Windows\System32\rasadhlp.dll') {
			$detection = [TrawlerDetection]::new(
				'Potential Hijacking of Autodial DLL',
				[TrawlerRiskPriority]::VeryHigh,
				'Registry',
				"T1546: Event Triggered Execution",
				"Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
			)
			$State.WriteDetection($detection)
		}
	}
}

function Test-HTMLHelpDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking HTML Help (.chm) DLL")
	$basepath = "{0}\Software\Microsoft\HtmlHelp Author"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath -f $p
		if (-not ($State.TestPathAsRegistry($path))) {
			continue 
		}

		foreach ($item in Get-TrawlerItemData -Path $path -ItemType ItemProperty -AsRegistry) {
			if ($item.Name -eq 'location') {
				$detection = [TrawlerDetection]::new(
					'Potential CHM DLL Hijack',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1546: Event Triggered Execution",
					"Key Location: $path, Entry Name: " + $item.Name + ", Entry Value: " + $item.Value
				)

				$State.WriteDetection($detection)
			}
		}
	}
}

<#
# Start T1546.001
#>

function Test-AssociationHijack {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking File Associations")
	$homedrive = $($State.Drives.AssumedHomeDrive)

	$value_regex_lookup = @{
		accesshtmlfile            = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office.*\\MSACCESS.EXE`"";
		batfile                   = '"%1" %';
		certificate_wab_auto_file = "`"$homedrive\\Program Files\\Windows Mail\\wab.exe`" /certificate `"%1`"";
		"chm.file"                = "`"$homedrive\\Windows\\hh.exe`" %1"
		cmdfile                   = '"%1" %';
		comfile                   = '"%1" %';
		desktopthemepackfile      = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1";
		evtfile                   = "$homedrive\\Windows\\system32\\eventvwr.exe /l:`"%1`"";
		evtxfile                  = "$homedrive\\Windows\\system32\\eventvwr.exe /l:`"%1`"";
		exefile                   = '"%1" %\*';
		hlpfile                   = "$homedrive\\Windows\\winhlp32.exe %1";
		mscfile                   = "$homedrive\\Windows\\system32\\mmc.exe `"%1`" %\*";
		powerpointhtmlfile        = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office16\\POWERPNT.EXE`"";
		powerpointxmlfile         = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office16\\POWERPNT.EXE`"";
		prffile                   = "`"$homedrive\\Windows\\System32\\rundll32.exe`" `"$homedrive\\Windows\\System32\\msrating.dll`",ClickedOnPRF %1";
		ratfile                   = "`"$homedrive\\Windows\\System32\\rundll32.exe`" `"$homedrive\\Windows\\System32\\msrating.dll`",ClickedOnRAT %1";
		regfile                   = "regedit.exe `"%1`""
		scrfile                   = "`"%1`" /S"
		themefile                 = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1"
		themepackfile             = "$homedrive\\Windows\\system32\\rundll32.exe $homedrive\\Windows\\system32\\themecpl.dll,OpenThemeAction %1"
		wbcatfile                 = "$homedrive\\Windows\\system32\\sdclt.exe /restorepage"
		wcxfile                   = "`"$homedrive\\Windows\\System32\\xwizard.exe`" RunWizard /u {.*} /z%1"
		"wireshark-capture-file"  = "`"$homedrive\\.*\\Wireshark.exe`" `"%1`""
		wordhtmlfile              = "`"$homedrive\\Program Files\\Microsoft Office\\Root\\Office.*\\WINWORD.EXE`""
	}

	# This specifically uses the list of CLASSES associated with each user, rather than the user hives directly
	$basepath = "Registry::HKEY_CURRENT_USER"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			foreach ($item in Get-TrawlerChildItem -Path $path) {
				$path = $item.Name
				if ($path.EndsWith('file')) {
					$basefile = $path.Split("\")[-1]
					$open_path = $path + "\shell\open\command"
					if (Test-Path -Path "Registry::$open_path") {
						Get-TrawlerItemData -Path $open_path -ItemType ItemProperty -AsRegistry | ForEach-Object {
							if ($_.Name -ne '(default)') {
								continue 
							}

							$exe = $_.Value
							if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($open_path, $exe, 'AssociationHijack'))) {
								continue
							}

							if ($value_regex_lookup.ContainsKey($basefile)) {
								if ($exe -notmatch $value_regex_lookup[$basefile]) {
									$detection = [TrawlerDetection]::new(
										'Possible File Association Hijack - Mismatch on Expected Value',
										[TrawlerRiskPriority]::High,
										'Registry',
										"T1546.001: Event Triggered Execution: Change Default File Association",
										"FileType: " + $open_path + ", Expected Association: " + $value_regex_lookup[$basefile] + ", Current Association: " + $exe
									)
									$State.WriteDetection($detection)
									return
								}
								else {
									return
								}
							}

							if ($exe -match ".*\.exe.*\.exe") {
								$detection = [TrawlerDetection]::new(
									'Possible File Association Hijack - Multiple EXEs',
									[TrawlerRiskPriority]::High,
									'Registry',
									"T1546.001: Event Triggered Execution: Change Default File Association",
									"FileType: " + $open_path + ", Current Association: " + $exe
								)
								$State.WriteDetection($detection)
								return
							}
							if (Test-SuspiciousTerms -Value $exe) {
								$detection = [TrawlerDetection]::new(
									'Possible File Association Hijack - Suspicious Keywords',
									[TrawlerRiskPriority]::High,
									'Registry',
									"T1546.001: Event Triggered Execution: Change Default File Association",
									"FileType: " + $open_path + ", Current Association: " + $exe
								)
								$State.WriteDetection($detection)
							}
						}
					}
				}
			}
		}
	}

	$basepath = "Registry::$($State.Drives.Hklm)SOFTWARE\Classes"
	if (-not (Test-Path -Path $basepath)) {
		return 
	}

	foreach ($item in Get-TrawlerChildItem -Path $basepath) {
		$path = $item.Name
		if ($path.EndsWith('file')) {
			$basefile = $path.Split("\")[-1]
			$open_path = $path + "\shell\open\command"
			if (Test-Path -Path "Registry::$open_path") {
				Get-TrawlerItemData -Path $open_path -ItemType ItemProperty -AsRegistry | ForEach-Object {
					if ($_.Name -eq '(default)') {
						#Write-Host $open_path $_.Value
						$exe = $_.Value

						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($open_path, $exe, 'AssociationHijack'))) {
							continue
						}

						if ($value_regex_lookup.ContainsKey($basefile)) {
							if ($exe -notmatch $value_regex_lookup[$basefile]) {
								$detection = [TrawlerDetection]::new(
									'Possible File Association Hijack - Mismatch on Expected Value',
									[TrawlerRiskPriority]::High,
									'Registry',
									"T1546.001: Event Triggered Execution: Change Default File Association",
									"FileType: " + $open_path + ", Expected Association: " + $value_regex_lookup[$basefile] + ", Current Association: " + $exe
								)
								$State.WriteDetection($detection)
								return
							}
							else {
								return
							}
						}

						if ($exe -match ".*\.exe.*\.exe") {
							$detection = [TrawlerDetection]::new(
								'Possible File Association Hijack - Multiple EXEs',
								[TrawlerRiskPriority]::High,
								'Registry',
								"T1546.001: Event Triggered Execution: Change Default File Association",
								"FileType: " + $open_path + ", Current Association: " + $exe
							)
							$State.WriteDetection($detection)
							return
						}
						if (Test-SuspiciousTerms -Value $exe) {
							$detection = [TrawlerDetection]::new(
								'Possible File Association Hijack - Suspicious Keywords',
								[TrawlerRiskPriority]::High,
								'Registry',
								"T1546.001: Event Triggered Execution: Change Default File Association",
								"FileType: " + $open_path + ", Current Association: " + $exe
							)
							$State.WriteDetection($detection)
						}
					}
				}
			}
		}
	}
}

<#
# Start T1546.002
#>

function Test-ScreenSaverEXE {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking ScreenSaver exe")
	$basepath = "{0}\Control Panel\Desktop"
	foreach ($userDrive in $State.Drives.CurrentUsers) {
		$path = $basepath -f $userDrive
		if (-not ($State.TestPathAsRegistry($path))) {
			continue 
		}

		Get-TrawlerItemData -Path $path -ItemType ItemProperty -AsRegistry | ForEach-Object {
			if ($_.Name -eq "SCRNSAVE.exe") {
				$detection = [TrawlerDetection]::new(
					'Potential Persistence via ScreenSaver Executable Hijack',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1546.002: Event Triggered Execution: Screensaver",
					"Key Location: HKCU\Control Panel\Desktop, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				)
				$State.WriteDetection($detection)
			}
		}
	}
}

<#
# Start T1546.003
#>

function Test-WMIConsumers {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Drive Retargeting..maybe
	# https://netsecninja.github.io/dfir-notes/wmi-forensics/
	# https://github.com/davidpany/WMI_Forensics
	# https://github.com/mandiant/flare-wmi/blob/master/WMIParser/WMIParser/ActiveScriptConsumer.cpp
	# This would require building a binary parser in PowerShell..difficult.
	if ($drivechange) {
		$State.WriteMessage("Skipping WMI Analysis - No Drive Retargeting [yet]")
		return
	}

	$State.WriteMessage("Checking WMI Consumers")
	$consumers = Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object *

	foreach ($consumer in $consumers) {
		if ($consumer.ScriptingEngine) {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($consumer.Name, $consumer.ScriptFileName, 'WMI Consumers'))) {
				continue
			}

			$detection = [TrawlerDetection]::new(
				'WMI ActiveScript Consumer',
				[TrawlerRiskPriority]::High,
				'WMI',
				"T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription",
				"Consumer Name: " + $consumer.Name + ", Script Name: " + $consumer.ScriptFileName + ", Script Text: " + $consumer.ScriptText
			)
			$State.WriteDetection($detection)
		}
		if ($consumer.CommandLineTemplate) {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($consumer.Name, $consumer.CommandLineTemplate, 'WMI Consumers'))) {
				continue
			}
			
			$detection = [TrawlerDetection]::new(
				'WMI CommandLine Consumer',
				[TrawlerRiskPriority]::High,
				'WMI',
				"T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription",
				"Consumer Name: " + $consumer.Name + ", Executable Path: " + $consumer.ExecutablePath + ", CommandLine Template: " + $consumer.CommandLineTemplate
			)
			$State.WriteDetection($detection)
		}
	}
}

<#
# Start T1546.007
#>

function Test-NetSHDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking NetSH DLLs")
	$standard_netsh_dlls = @(
		"authfwcfg.dll",
		"dhcpcmonitor.dll",
		"dot3cfg.dll",
		"fwcfg.dll",
		"hnetmon.dll",
		"ifmon.dll",
		"napmontr.dll",
		"netiohlp.dll",
		"netprofm.dll",
		"nettrace.dll",
		"nshhttp.dll",
		"nshipsec.dll",
		"nshwfp.dll",
		"p2pnetsh.dll",
		"peerdistsh.dll",
		"rasmontr.dll",
		"rpcnsh.dll",
		"WcnNetsh.dll",
		"whhelper.dll",
		"wlancfg.dll",
		"wshelper.dll",
		"wwancfg.dll"
	)

	$path = "Registry::$($State.Drives.Hklm)SOFTWARE\Microsoft\Netsh"

	if (Test-Path -Path $path) {
		Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
			if ($_.Value -in $standard_netsh_dlls) {
				continue
			}

			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'NetshDLLs'))) {
				continue
			}

			$detection = [TrawlerDetection]::new(
				'Potential Persistence via Netsh Helper DLL Hijack',
				[TrawlerRiskPriority]::High,
				'Registry',
				"T1546.007: Event Triggered Execution: Netsh Helper DLL",
				"Key Location: HKLM\SOFTWARE\Microsoft\Netsh, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
			)
			$State.WriteDetection($detection)
		}
	}
}

<#
# Start T1546.008
#>

function Test-KnownHijacks {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	$State.WriteMessage("Checking Known Hijacks")

	$knownHijackPaths = @(
		"{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
		"{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
	)

	foreach ($path in $knownHijackPaths) {
		$path = $path -f $State.Drives.Hklm
		if (-not ($State.TestPathAsRegistry($path))) {
			continue
		}

		$detection = [TrawlerDetection]::new(
			'Potential utilman.exe Registry Persistence',
			[TrawlerRiskPriority]::High,
			'Registry',
			"T1546.008: Event Triggered Execution: Accessibility Features",
			"Review Data for Key: $path"
		)

		$State.WriteDetection($detection)
	}
}

function Test-ModifiedWindowsAccessibilityFeature {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# TODO - Consider allow-listing here
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Accessibility Binaries")

	$knownFiles = @(
		"{0}\Program Files\Common Files\microsoft shared\ink\HID.dll"
		"{0}\Windows\System32\AtBroker.exe",
		"{0}\Windows\System32\DisplaySwitch.exe",
		"{0}\Windows\System32\Magnify.exe",
		"{0}\Windows\System32\Narrator.exe",
		"{0}\Windows\System32\osk.exe",
		"{0}\Windows\System32\sethc.exe",
		"{0}\Windows\System32\utilman.exe"
	)

	foreach ($file in $knownFiles) { 
		$file = $file -f $State.Drives.HomeDrive
		$fdata = Get-Item $file -ErrorAction SilentlyContinue | Select-Object CreationTime, LastWriteTime
		if ($fdata.CreationTime) {
			if ($fdata.CreationTime.ToString() -ne $fdata.LastWriteTime.ToString()) {
				$detection = [TrawlerDetection]::new(
					'Potential modification of Windows Accessibility Feature',
					[TrawlerRiskPriority]::High,
					'Windows',
					"T1546.008: Event Triggered Execution: Accessibility Features",
					[PSCustomObject]@{
						File     = $file
						Created  = $fdata.CreationTime
						Modified = $fdata.LastWriteTime
					}
				)
				$State.WriteDetection($detection)
			}
		}
	}
}

<#
# Start T1546.009
#>

function Test-AppCertDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking AppCert DLLs")
	$standard_appcert_dlls = @()
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\$($State.Drives.CurrentControlSet)\Control\Session Manager\AppCertDlls"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Value -notin $standard_appcert_dlls) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'AppCertDLLs'))) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'Potential Persistence via AppCertDLL Hijack',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1546.009: Event Triggered Execution: AppCert DLLs",
					"Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				)
				$State.WriteDetection($detection)
			}
		}
		
	}
}

<#
# Start T1546.010
#>

function Test-AppInitDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking AppInit DLLs")
	$knownPaths = @(
		"{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
		"{0}Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
	)

	foreach ($path in $knownPaths) {
		$path = $path -f $State.Drives.Hklm

		if (-not ($State.TestPathAsRegistry($path))) {
			continue
		}

		Get-TrawlerItemData -Path $Path -ItemType ItemProperty -AsRegistry | ForEach-Object {
			if ($_.Name -eq 'AppInit_DLLs' -and $_.Value -ne '') {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'AppInitDLLs'))) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'Potential AppInit DLL Persistence',
					[TrawlerRiskPriority]::Medium,
					'Registry',
					"T1546.010: Event Triggered Execution: AppInit DLLs",
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

<#
# Start T1546.011
#>

function Test-ApplicationShims {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	$State.WriteMessage("Checking Application Shims")
	# TODO - Also check HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
	$knownPaths = @(
		"{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"
		"{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"
	)

	foreach ($path in $knownPaths) {
		$path = $path -f $State.Drives.Hklm
		if (-not ($State.TestPathAsRegistry($path))) {
			return 
		}
		
		Get-TrawlerItemData -Path $path -ItemType ItemProperty -AsRegistry | ForEach-Object {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'AppShims'))) {
				continue
			}
	
			$State.WriteDetection([TrawlerDetection]::new(
					'Potential Application Shimming Persistence',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1546.011: Event Triggered Execution: Application Shimming",
					[PSCustomObject]@{
						KeyLocation = $path
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				))
		}
	}
}

<#
# Start T1546.012
#>

function Test-IFEO {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Image File Execution Options")
	$path = "Registry::{0}SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -f $($State.Drives.Hklm)
	if (-not (Test-Path -Path $path)) {
		continue 
	}

	foreach ($item in Get-TrawlerChildItem -Path $path) {
		$data = Get-TrawlerItemProperty -Path $item.Name -AsRegistry
		if ($data.Debugger) {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.Debugger, 'IFEO'))) {
				continue
			}

			$detection = [TrawlerDetection]::new(
				'Potential Image File Execution Option Debugger Injection',
				[TrawlerRiskPriority]::High,
				'Registry',
				"T1546.012: Event Triggered Execution: Image File Execution Options Injection",
				[PSCustomObject]@{
					RegistryPath = $item.name
					Debugger     = $data.Debugger
				}
			)

			$State.WriteDetection($detection)
		}
	}
}

function Test-RegistryChecks {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# DEPRECATED FUNCTION
	#TODO - Inspect File Command Extensions to hunt for anomalies
	# https://attack.mitre.org/techniques/T1546/001/

	# COM Object Hijack Scan
	# NULL this out for now since it should be covered in following COM functionality - this function is deprecated
	if (Test-Path -Path "Registry::HKCU\SOFTWARE\Classes\CLSIDNULL") {
		$items = Get-ChildItem -Path "Registry::HKCU\SOFTWARE\Classes\CLSID" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$children = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			foreach ($child in $children) {
				$path = "Registry::" + $child.Name
				$data = Get-Item -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
				if ($data.Name -match '.*InprocServer32') {
					$datum = Get-ItemProperty $path
					$datum.PSObject.Properties | ForEach-Object {
						if ($_.Name -eq '(default)') {
							$detection = [TrawlerDetection]::new(
								'Potential COM Hijack',
								[TrawlerRiskPriority]::High,
								'Registry',
								"T1546.012: Event Triggered Execution: Image File Execution Options Injection",
								"Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
							)
							#$State.WriteDetection($detection)
							# This is now handled by Test-COM-Hijacks along with HKLM and HKCR checks (which should be identical)
						}
					}
				}
			}
		}
	}
}

function Test-SilentProcessExitMonitoring {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking SilentProcessExit Monitoring")
	$path = "Registry::{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" -f $($State.Drives.Hklm)
	if (-not (Test-Path -Path $path)) {
		return 
	}
	
	foreach ($item in Get-TrawlerChildItem -Path $path) {
		$data = Get-TrawlerItemProperty -Path $item.Name -AsRegistry
		if ($data.MonitorProcess) {
			if ($data.ReportingMode) {
				$data.ReportingMode = 'NA'
			}

			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $data.MonitorProcess, 'SilentProcessExit'))) {
				continue
			}

			#allowtable_silentprocessexit
			$detection = [TrawlerDetection]::new(
				'Process Launched on SilentProcessExit',
				[TrawlerRiskPriority]::High,
				'Registry',
				"T1546.012: Event Triggered Execution: Image File Execution Options Injection",
				[PSCustomObject]@{
					MonitoredProcess = $item.Name
					LaunchedProcess  = $data.MonitorProcess
					ReportingMode    = $data.ReportingMode
				}
			)

			$State.WriteDetection($detection)
		}
	}
}

<#
# Start T1546.013
#>

function Test-PowerShellProfiles {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# PowerShell profiles may be abused by adversaries for persistence.
	# Supports Drive Retargeting
	# TODO - Add check for 'suspicious' content
	# TODO - Consider allow-listing here

	# $PSHOME\Profile.ps1
	# $PSHOME\Microsoft.PowerShell_profile.ps1
	# $HOME\Documents\PowerShell\Profile.ps1
	# $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
	$State.WriteMessage("Checking PowerShell Profiles")

	$knownPowerShellProfilePaths = @(
		"{0}\Users\{1}\Documents\WindowsPowerShell\profile.ps1"
		"{0}\Users\{1}\Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1"
		"{0}\Users\{1}\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
	)

	$retrievedPowerShellProfiles = [System.Collections.ArrayList]::new()

	if ($drivechange) {
		# TODO - Investigate whether these paths can be retrieved from the HKLM HIVE dynamically
		$retrievedPowerShellProfiles.AddRange(@(
				"{0}\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
				"{0}\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1"
			))
	}
	else {
		$retrievedPowerShellProfiles.AddRange(@(
				$PROFILE.AllUsersAllHosts
				$PROFILE.AllUsersCurrentHost
			))
	}

	foreach ($path in $retrievedPowerShellProfiles) {
		$path = $path -f $($State.Drives.HomeDrive)

		if (-not (Test-Path -Path $path)) {
			continue
		}

		$State.WriteDetection([TrawlerDetection]::new(
				'Review: Global Custom PowerShell Profile',
				[TrawlerRiskPriority]::Medium,
				'PowerShell',
				"T1546.013: Event Triggered Execution: PowerShell Profile",
				"Profile: " + $path
			))
	}

	foreach ($name in Get-ChildItem "$($State.Drives.HomeDrive)\Users" -Directory | Select-Object Name) {
		foreach ($path in $knownPowerShellProfilePaths) {
			$path = $path -f $($State.Drives.HomeDrive), $name

			if (-not (Test-Path -Path $path)) {
				continue 
			}

			$State.WriteDetection([TrawlerDetection]::new(
					'Review: Custom PowerShell Profile',
					[TrawlerRiskPriority]::Medium,
					'PowerShell',
					"T1546.013: Event Triggered Execution: PowerShell Profile",
					[PSCustomObject]@{
						User        = $name
						ProfilePath = $path
					}
				))
		}
	}
}

<#
# Start T1546.015
#>

function Test-ComHijacks {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)

	if (-not (Test-Path -Path $Path)) {
		return
	}
    
	$rootItems = Get-TrawlerChildItem -Path $Path

	foreach ($item in $rootItems) {
		foreach ($childItem in Get-TrawlerChildItem -Path "Registry::$($item.Name)") {
			$dataPath = "Registry::$($childItem.Name)"
			$data = Get-TrawlerItem -Path $dataPath

			if (-not ($data.Name -match '.*InprocServer32')) {
				continue
			}

			foreach ($property in Get-ItemProperty $dataPath) {
				if (-not ($_.Name -eq '(Default)')) {
					continue
				}

				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($data.Name, $_.Value, 'COM'))) {
					continue
				}

				if ($TrawlerState.LoadSnapshot) {
					$detection = [TrawlerDetection]::new(
						'Allowlist Mismatch: COM Hijack',
						[TrawlerRiskPriority]::Medium,
						'Registry',
						"T1546.015: Event Triggered Execution: Component Object Model Hijacking",
						"Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
					)

					$result = Assert-IsAllowed $allowtable_com $data.Name $_.Value $detection
					if ($result) {
						continue
					}
				}

				$verified_match = Find-IfValueExistsInComTables -ComTables $ComTables -Key $data.Name -Value $_.Value
                
				if (!($verified_match) -or $_.Value -match "$env:homedrive\\Users\\(public|administrator|guest).*") {
					$detection = [TrawlerDetection]::new(
						'Potential COM Hijack',
						[TrawlerRiskPriority]::Medium,
						'Registry',
						"T1546.015: Event Triggered Execution: Component Object Model Hijacking",
						"Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
}

function Test-WellKnownCOM {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Drive Retargeting
	# TODO - Add the same HKLM Check
	$State.WriteMessage("Checking well-known COM hijacks")

	$knownUUIDs = @(
		"{42aedc87-2188-41fd-b9a3-0c966feabec1}" # shell32.dll Hijack
		"{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}" # WBEM Subsystem
	)

	$basepath = "Registry::{0}\Software\Classes\CLSID\{1}\InprocServer32"

	foreach ($userDrive in $State.Drives.CurrentUsers) {
		foreach ($uuid in $knownUUIDs) {
			$path = $basepath -f $userDrive, $uuid

			if (-not (Test-Path -Path $path)) {
				continue
			}

			Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
				$State.WriteDetection([TrawlerDetection]::new(
						'Potential WBEM Subsystem Hijack for Persistence',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1546.015: Event Triggered Execution: Component Object Model Hijacking",
						[PSCustomObject]@{
							KeyLocation = $path.Trim("Registry::")
							EntryName   = $_.Name
							EntryValue  = $_.Value
						}
					))
			}
		}
	}
}

function Find-IfValueExistsInComTables {
	[CmdletBinding()]
	param (
		[Parameter()]
		$ComTables,
		[Parameter()]
		$Key,
		[Parameter()]
		$Value
	)

	return Find-ValueInHashTable -HashTable $ComTables.DefaultHkcrComLookups -Key $Key -Value $Value -or Find-ValueInHashTable -HashTable $ComTables.Server2022Coms -Key $Key -Value $Value
}

function Find-ValueInHashTable {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		$HashTable,
		[Parameter(Mandatory)]
		$Key,
		[Parameter(Mandatory)]
		$Value
	)

	$hashTableValue = $HashTable[$Key]

	if ($hashTableValue) {
		return $Value -match $hashTableValue
	}
	else {
		return $false
	}
}

<# REWRITE THE BELOW INTO THE TEST-COMHIJACKS CMD #>
function Test-COM-Hijacks {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking COM Classes")
	# TODO - Consider NOT alerting when we don't have a 'known-good' entry for the CLSID in question
	# TODO - Some regex appears to be non-functional, especially on HKU inspection - need to figure out why/troubleshoot
	# TODO - Inspect TreatAs options
	# Malware will typically target 'well-known' keys that are present in default versions of Windows - that should be enough for most situations and help to reduce noise.
	$ComTables = Build-ComPaths -HomeDrive $($State.Drives.AssumedHomeDrive)

	# HKCR
	$path = "HKCR\CLSID_SKIP"
	Test-ComHijacks -Path "Registry::HKCR\CLSID_SKIP" -ComTables $ComTables -TrawlerState $ERROR

	## HKLM
	$default_hklm_com_lookups = @{}
	$default_hklm_com_server_lookups = @{}
	$local_regretarget = $($State.Drives.Hklm) + "SOFTWARE\Classes"
	#Write-Host $local_regretarget
	foreach ($hash in $ComTables.DefaultHkcrComLookups.GetEnumerator()) {
		$new_name = ($hash.Name).Replace("HKEY_CLASSES_ROOT", $local_regretarget)
		$default_hklm_com_lookups["$new_name"] = $hash.Value
	}
	foreach ($hash in $ComTables.Server2022Coms.GetEnumerator()) {
		$new_name = ($hash.Name).Replace("HKEY_CLASSES_ROOT", $local_regretarget)
		$default_hklm_com_server_lookups["$new_name"] = $hash.Value
	}

	#test AD5FBC96-ACFE-46bd-A2E2-623FD110C74C
	$local_regretarget2 = "$($State.Drives.Hklm)SOFTWARE\Classes\CLSID"
	#$path = "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID"
	$path = $local_regretarget2
	if (Test-Path -Path "Registry::$path") {
		$items = Get-ChildItem -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$children = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			foreach ($child in $children) {
				$path = "Registry::" + $child.Name
				$data = Get-Item -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
				if ($data.Name -match '.*InprocServer32') {
					$datum = Get-ItemProperty $path
					$datum.PSObject.Properties | ForEach-Object {
						if ($_.Name -eq '(Default)') {
							if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($data.Name, $_.Value, 'COM'))) {
								continue
							}

							$verified_match = $false
							if ($default_hklm_com_lookups.ContainsKey($data.Name)) {
								try {
									if ($_.Value -match $default_hklm_com_lookups[$data.Name]) {
										$verified_match = $true
									}
								}
								catch {
									Write-Reportable-Issue "Regex Error while parsing string: $($default_hklm_com_lookups[$data.Name])"
								}
							}

							if ($default_hklm_com_server_lookups.ContainsKey($data.Name) -and $verified_match -ne $true) {
								try {
									if ($_.Value -match $default_hklm_com_server_lookups[$data.Name]) {
										$verified_match = $true
									}
								}
								catch {
									Write-Reportable-Issue "Regex Error while parsing string: $($default_hklm_com_server_lookups[$data.Name])"
								}
							}

							if ($verified_match -ne $true -or $_.Value -match "$env:homedrive\\Users\\(public|administrator|guest).*") {
								$detection = [TrawlerDetection]::new(
									'Potential COM Hijack',
									[TrawlerRiskPriority]::Medium,
									'Registry',
									"T1546.015: Event Triggered Execution: Component Object Model Hijacking",
									"Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
								)
								$State.WriteDetection($detection)
							}
						}
					}
				}
			}
		}
	}

	## HKCU/HKU
	$default_hkcu_com_lookups = @{}
	$default_hkcu_com_server_lookups = @{}
	foreach ($hash in $ComTables.DefaultHkcrComLookups) {
		foreach ($p in $State.Drives.CurrentUsers) {
			$new_name = ($hash.Name).Replace("HKEY_CLASSES_ROOT", "$p\CLSID")
			$default_hkcu_com_lookups["$new_name"] = $hash.Value
		}
	}
	foreach ($hash in $ComTables.Server2022Coms) {
		foreach ($p in $State.Drives.CurrentUsers) {
			$new_name = ($hash.Name).Replace("HKEY_CLASSES_ROOT", "$p\CLSID")
			$default_hkcu_com_server_lookups["$new_name"] = $hash.Value
		}
	}
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = "$p\CLSID"
		if (Test-Path -Path "Registry::$path") {
			$items = Get-ChildItem -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			foreach ($item in $items) {
				$path = "Registry::" + $item.Name
				$children = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
				foreach ($child in $children) {
					$path = "Registry::" + $child.Name
					$data = Get-Item -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
					if ($data.Name -match '.*InprocServer32') {
						$datum = Get-ItemProperty $path
						$datum.PSObject.Properties | ForEach-Object {
							if ($_.Name -eq '(Default)') {
								if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($data.Name, $_.Value, 'COM'))) {
									continue
								}

								$verified_match = $false

								if ($default_hkcu_com_lookups.ContainsKey($data.Name)) {
									try {
										if ($_.Value -match $default_hkcu_com_lookups[$data.Name]) {
											$verified_match = $true
										}
									}
									catch {
										Write-Reportable-Issue "Regex Error while parsing string: $($default_hkcu_com_lookups[$data.Name])"
									}
								}

								if ($default_hkcu_com_server_lookups.ContainsKey($data.Name) -and $verified_match -ne $true) {
									$regex = $default_hkcu_com_server_lookups[$data.Name]
									try {
										if ($_.Value -match $regex) {
											$verified_match = $true
										}
									}
									catch {
										Write-ReportableMessage -Message "Error while parsing string with Regex" -AdditionalInformation "String: $($_.Value)`n`tRegex: $($regex)"
									}
								}

								if ($verified_match -ne $true -or $_.Value -match "$env:homedrive\\Users\\(public|administrator|guest).*") {

									$detection = [TrawlerDetection]::new(
										'Potential COM Hijack',
										[TrawlerRiskPriority]::Medium,
										'Registry',
										"T1546.015: Event Triggered Execution: Component Object Model Hijacking",
										"Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
									)
									
									$State.WriteDetection($detection)
								}
							}
						}
					}
				}
			}
		}
	}
}

function Test-FolderOpen {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking FolderOpen Command")
	$basepath = "Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open\command"
	foreach ($p in $State.Drives.CurrentUsers) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-TrawlerItemProperty -Path $path
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'DelegateExecute') {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, 'FolderOpen'))) {
						continue
					}

					$detection = [TrawlerDetection]::new(
						'Potential Folder Open Hijack for Persistence',
						[TrawlerRiskPriority]::High,
						'Registry',
						"T1546.015: Event Triggered Execution: Component Object Model Hijacking",
						"Key Location: HKCU\Software\Classes\Folder\shell\open\command, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
}