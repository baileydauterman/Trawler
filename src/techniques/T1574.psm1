function Test-T1574 {
	[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [TrawlerState]
        $State
    )

	Test-MSDTCDll $State
	Test-PeerDistExtensionDll $State
	Test-InternetSettingsLUIDll $State
	Test-BIDDll $State
	Test-WindowsUpdateTestDlls $State
	Test-MiniDumpAuxiliaryDLLs $State
	Test-ExplorerHelperUtilities $State
	Test-ProcessModules $State
	Test-WindowsUnsignedFiles $State
	Test-ErrorHandlerCMD $State
	Test-KnownManagedDebuggers $State
	Test-Wow64LayerAbuse $State
	Test-SEMgrWallet $State
	Test-WERRuntimeExceptionHandlers $State
	Test-TerminalServicesInitialProgram $State
	Test-EventViewerMSC $State
	Test-RDPStartupPrograms $State
	Test-PATHHijacks $State
	Test-ServiceHijacks $State
}
function Test-MSDTCDll {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
	$State.WriteMessage("Checking MSDTC DLL Hijack")
	$matches = @{
		"OracleOciLib"     = "oci.dll"
		"OracleOciLibPath" = "$env_assumedhomedrive\Windows\system32"
		"OracleSqlLib"     = "SQLLib80.dll"
		"OracleSqlLibPath" = "$env_assumedhomedrive\Windows\system32"
		"OracleXaLib"      = "xa80.dll"
		"OracleXaLibPath"  = "$env_assumedhomedrive\Windows\system32"
	}
	$path = "$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\MSDTC\MTxOCI"
	if (Test-Path -Path "Registry::$path") {
		$data = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$data.PSObject.Properties | ForEach-Object {
			if ($matches.ContainsKey($_.Name)) {
				if ($_.Value -ne $matches[$_.Name]) {
					$detection = [PSCustomObject]@{
						Name      = 'MSDTC Key/Value Mismatch'
						Risk      = 'Medium'
						Source    = 'Windows MSDTC'
						Technique = "T1574: Hijack Execution Flow"
						Meta      = "Key: " + $path + ", Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Expected Value: " + $matches[$_.Name]
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Test-PeerDistExtensionDll {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Targeting
	$State.WriteMessage("Checking PeerDistExtension DLL")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension"
	$expected_value = "peerdist.dll"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "PeerdistDllName" -and $_.Value -ne $expected_value) {
				$detection = [PSCustomObject]@{
					Name      = 'PeerDist DLL does not match expected value'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Expected Value: $expected_value, Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-InternetSettingsLUIDll {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking InternetSettings DLL")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\LUI"
	$expected_value = "$env_assumedhomedrive\Windows\system32\wininetlui.dll!InternetErrorDlgEx"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "0" -and $_.Value -ne $expected_value) {
				$detection = [PSCustomObject]@{
					Name      = 'InternetSettings LUI Error DLL does not match expected value'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Expected Value: $expected_value, Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-BIDDll {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	$State.WriteMessage("Checking BID DLL")
	$paths = @(
		"Registry::$($State.DriveTargets.Hklm)Software\Microsoft\BidInterface\Loader"
		"Registry::$($State.DriveTargets.Hklm)software\Wow6432Node\Microsoft\BidInterface\Loader"

	)
	$expected_values = @(
		"$env:homedrive\\Windows\\Microsoft\.NET\\Framework\\.*\\ADONETDiag\.dll"
		"$env:homedrive\\Windows\\SYSTEM32\\msdaDiag\.dll"

	)
	foreach ($path in $paths) {
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq ":Path") {
					Write-SnapshotMessage -Key $path -Value $_.Value -Source 'BIDDLL'

					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_biddll $path $_.Value
						if ($result) {
							continue
						}
					}
					$match = $false
					foreach ($val in $expected_values) {
						if ($_.Value -match $val) {
							$match = $true
							break
						}
					}
					if ($match -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Non-Standard Built-In Diagnostics (BID) DLL'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Test-WindowsUpdateTestDlls {
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	$State.WriteMessage("Checking Windows Update Test")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Test"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -in "EventerHookDll", "AllowTestEngine", "AlternateServiceStackDLLPath") {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'WinUpdateTestDLL'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_winupdatetest $path $_.Value
					if ($result) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Windows Update Test DLL Exists'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1574: Hijack Execution Flow"
						Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Test-MiniDumpAuxiliaryDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	$State.WriteMessage("Checking MiniDumpAuxiliary DLLs")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls"
	$allow_list = @(
		"$env:homedrive\\Program Files\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\coreclr\.dll"
		"$env:homedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\(mscorwks|clr)\.dll"
		"$env:homedrive\\Windows\\System32\\(chakra|jscript.*|mrt.*)\.dll"

	)
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			Write-SnapshotMessage -Key $path -Value $_.Name -Source 'MiniDumpAuxiliaryDLL'

			$pass = $false
			if ($loadsnapshot) {
				$result = Assert-IsAllowed $allowlist_minidumpauxdlls $path $_.Name
				if ($result) {
					$pass = $true
				}
			}
			$matches_good = $false
			foreach ($allowed_item in $allow_list) {
				if ($_.Name -match $allowed_item) {
					$matches_good = $true
					break
				}
			}
			if ($matches_good -eq $false -and $pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Non-Standard MiniDumpAuxiliary DLL'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta      = "Key Location: $path, DLL: " + $_.Name
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-ExplorerHelperUtilities {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Explorer Helper exes")
	$paths = @(
		"Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\BackupPath"
		"Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\cleanuppath"
		"Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath"
	)
	$allowlisted_explorer_util_paths = @(
		"$env:SYSTEMROOT\system32\sdclt.exe"
		"$env:SYSTEMROOT\system32\cleanmgr.exe /D %c"
		"$env:SYSTEMROOT\system32\dfrgui.exe"
		"$env:SYSTEMROOT\system32\wbadmin.msc"
	)
	foreach ($path in $paths) {
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(Default)' -and $_.Value -ne '""' -and $_.Value -notin $allowlisted_explorer_util_paths) {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'ExplorerHelpers'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_explorerhelpers $_.Value $_.Value
						if ($result -eq $true) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Explorer\MyComputer Utility Hijack'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", DLL: " + $_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Test-ProcessModules {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Does not support Drive Retargeting
	if ($drivechange) {
		$State.WriteMessage("Skipping Phantom DLLs - No Drive Retargeting")
		return
	}
	$State.WriteMessage("Checking 'Phantom' DLLs")
	$processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName, CreationDate, CommandLine, ExecutablePath, ParentProcessId, ProcessId
	$suspicious_unsigned_dll_names = @(
		"cdpsgshims.dll",
		"diagtrack_win.dll",
		"EdgeGdi.dll",
		"Msfte.dll",
		"phoneinfo.dll",
		"rpcss.dll",
		"sapi_onecore.dll",
		"spreview.exewdscore.dll",
		"Tsmsisrv.dll",
		"TSVIPSrv.dll",
		"Ualapi.dll",
		"UsoSelfhost.dll",
		"wbemcomn.dll",
		"WindowsCoreDeviceInfo.dll",
		"windowsperformancerecordercontrol.dll",
		"wlanhlp.dll",
		"wlbsctrl.dll",
		"wow64log.dll",
		"WptsExtensions.dll"
		"fveapi.dll"
	)
	foreach ($process in $processes) {
		$modules = Get-Process -id $process.ProcessId -ErrorAction SilentlyContinue  | Select-Object -ExpandProperty modules -ErrorAction SilentlyContinue | Select-Object Company, FileName, ModuleName
		if ($modules -ne $null) {
			foreach ($module in $modules) {
				if ($module.ModuleName -in $suspicious_unsigned_dll_names) {
					Write-SnapshotMessage -Key $module.FileName -Value $module.FileName -Source 'Modules'

					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_modules $module.FileName $module.FileName
						if ($result) {
							continue
						}
					}
					$signature = Get-AuthenticodeSignature $module.FileName
					if ($signature.Status -ne 'Valid') {
						$item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
						$detection = [PSCustomObject]@{
							Name      = 'Suspicious Unsigned DLL with commonly-masqueraded name loaded into running process.'
							Risk      = 'Very High'
							Source    = 'Processes'
							Technique = "T1574: Hijack Execution Flow"
							Meta      = "DLL: " + $module.FileName + ", Process Name: " + $process.ProcessName + ", PID: " + $process.ProcessId + ", Execuable Path: " + $process.ExecutablePath + ", DLL Creation Time: " + $item.CreationTime + ", DLL Last Write Time: " + $item.LastWriteTime
						}
						Write-Detection $detection
					}
					else {
						$item = Get-ChildItem -Path $module.FileName -File -ErrorAction SilentlyContinue | Select-Object *
						$detection = [PSCustomObject]@{
							Name      = 'Suspicious DLL with commonly-masqueraded name loaded into running process.'
							Risk      = 'High'
							Source    = 'Processes'
							Technique = "T1574: Hijack Execution Flow"
							Meta      = "DLL: " + $module.FileName + ", Process Name: " + $process.ProcessName + ", PID: " + $process.ProcessId + ", Execuable Path: " + $process.ExecutablePath + ", DLL Creation Time: " + $item.CreationTime + ", DLL Last Write Time: " + $item.LastWriteTime
						}
						# TODO - This is too noisy to use as-is - these DLLs get loaded into quite a few processes.
						# Write-Detection $detection
					}
				}
			}
		}
	}
}

function Test-WindowsUnsignedFiles {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting - Not actually sure if this will work though
	$State.WriteMessage("Checking Unsigned Files")
	$scan_paths = @(
		"$env_homedrive\Windows",
		"$env_homedrive\Windows\System32",
		"$env_homedrive\Windows\System"
		"$env_homedrive\Windows\temp"
	)
	#allowlist_unsignedfiles
	foreach ($path in $scan_paths) {
		$files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".dll", ".exe" } | Select-Object *
		foreach ($file in $files) {
			$sig = Get-AuthenticodeSignature $file.FullName
			if ($sig.Status -ne 'Valid') {
				$item = Get-ChildItem -Path $file.FullName -File -ErrorAction SilentlyContinue | Select-Object *
				Write-SnapshotMessage -Key $file.FullName -Value $file.FullName -Source 'UnsignedWindows'

				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_unsignedfiles $file.FullName $file.FullName
					if ($result) {
						continue
					}
				}
				$detection = [PSCustomObject]@{
					Name      = 'Unsigned DLL/EXE present in critical OS directory'
					Risk      = 'Very High'
					Source    = 'Windows'
					Technique = "T1574: Hijack Execution Flow"
					Meta      = "File: " + $file.FullName + ", Creation Time: " + $item.CreationTime + ", Last Write Time: " + $item.LastWriteTime
				}
				#Write-Host $detection.Meta
				Write-Detection $detection
			}
		}
	}
}

function Test-ErrorHandlerCMD {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Support Drive Retargeting
	$State.WriteMessage("Checking ErrorHandler.cmd")
	$path = "$env_homedrive\windows\Setup\Scripts\ErrorHandler.cmd"
	if (Test-Path $path) {

		$script_content_detection = $false
		try {
			$script_content = Get-Content $path
			foreach ($line_ in $script_content) {
				if ($line_ -match $suspicious_terms -and $script_content_detection -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Suspicious Content in ErrorHandler.cmd'
						Risk      = 'High'
						Source    = 'Windows'
						Technique = "T1574: Hijack Execution Flow"
						Meta      = "File: $path, Suspicious Line: +$line_"
					}
					Write-Detection $detection
					$script_content_detection = $true
				}
			}
		}
		catch {
		}
		if ($script_content_detection -eq $false) {
			$detection = [PSCustomObject]@{
				Name      = 'Review: ErrorHandler.cmd Existence'
				Risk      = 'High'
				Source    = 'Windows'
				Technique = "T1574: Hijack Execution Flow"
				Meta      = "File Location: $path"
			}
			Write-Detection $detection
		}
	}
}

function Test-KnownManagedDebuggers {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Can support drive retargeting
	$State.WriteMessage("Checking Known Managed Debuggers")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows NT\CurrentVersion\KnownManagedDebuggingDlls"
	$allow_list = @(
		"$env:homedrive\\Program Files\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\mscordaccore\.dll"
		"$env:homedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\mscordacwks\.dll"
		"$env:homedrive\\Windows\\System32\\mrt_map\.dll"
	)
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			Write-SnapshotMessage -Key $path -Value $_.Name -Source 'KnownManagedDebuggers'

			$pass = $false
			if ($loadsnapshot) {
				$result = Assert-IsAllowed $allowlist_knowndebuggers $path $_.Name
				if ($result) {
					$pass = $true
				}
			}
			$matches_good = $false
			foreach ($allowed_item in $allow_list) {
				if ($_.Name -match $allowed_item) {
					$matches_good = $true
					break
				}
			}
			if ($matches_good -eq $false -and $pass -and $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Non-Standard KnownManagedDebugging DLL'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta      = "Key Location: $path, DLL: " + $_.Name
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-Wow64LayerAbuse {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking WOW64 Compatibility DLLs")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Wow64\x86"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -ne "(Default)") {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'WOW64Compat'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_WOW64Compat $_.Name $_.Value
					if ($result) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Wow64\x86 DLL loaded into x86 process'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1574: Hijack Execution Flow"
						Meta      = "Key Location: $path, Target Process Name: " + $_.Name + " Loaded DLL: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Test-SEMgrWallet {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# TODO - Implement snapshot skipping
	# Supports Drive Retargeting
	$State.WriteMessage("Checking SEMgr Wallet DLLs")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\SEMgr\Wallet"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "DllName" -and $_.Value -notin "", "SEMgrSvc.dll") {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'SEMgr'

				$detection = [PSCustomObject]@{
					Name      = 'Potential SEMgr Wallet DLL Hijack'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1574: Hijack Execution Flow"
					Meta      = "Key Location: $path, Entry: " + $_.Name + " Loaded DLL: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-WERRuntimeExceptionHandlers {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Error Reporting Handler DLLs")
	$allowed_entries = @(
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft\\Edge\\Application\\.*\\msedge_wer\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Common Files\\Microsoft Shared\\ClickToRun\\c2r64werhandler\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\dotnet\\shared\\Microsoft\.NETCore\.App\\.*\\mscordaccore\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Google\\Chrome\\Application\\.*\\chrome_wer\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE.*\\msowercrash\.dll"
		"$env_assumedhomedrive\\Program Files( \(x86\))?\\Microsoft Visual Studio\\.*\\Community\\common7\\ide\\VsWerHandler\.dll"
		"$env_assumedhomedrive\\Windows\\Microsoft\.NET\\Framework64\\.*\\mscordacwks\.dll"
		"$env_assumedhomedrive\\Windows\\System32\\iertutil.dll"
		"$env_assumedhomedrive\\Windows\\System32\\msiwer.dll"
		"$env_assumedhomedrive\\Windows\\System32\\wbiosrvc.dll"
		"$env_assumedhomedrive\\(Program Files|Program Files\(x86\))\\Mozilla Firefox\\mozwer.dll"
	)
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {

			$verified_match = $false
			foreach ($entry in $allowed_entries) {
				#Write-Host $entry
				if ($_.Name -match $entry -and $verified_match -eq $false) {
					$verified_match = $true
				}
				else {
				}
			}

			if ($_.Name -ne "(Default)" -and $verified_match -eq $false) {
				Write-SnapshotMessage -Key $path -Value $_.Name -Source 'WERHandlers'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_werhandlers $path $_.Name
					if ($result) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential WER Helper Hijack'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1574: Hijack Execution Flow"
						Meta      = "Key Location: $path, DLL: " + $_.Name
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Test-TerminalServicesInitialProgram {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Terminal Services Initial Programs")
	$paths = @(
		"Registry::$($State.DriveTargets.Hklm)SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
		"Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Terminal Server\WinStations\RDP-Tcp"
	)
	$basepath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
	foreach ($p in $regtarget_hkcu_list) {
		$paths += $basepath.Replace("HKEY_CURRENT_USER", $p)
	}

	foreach ($path in $paths) {
		if (Test-Path -Path $path) {
			$finherit = $false
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'fInheritInitialProgram' -and $_.Value -eq "1") {
					$finherit = $true
				}
			}
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'InitialProgram' -and $_.Value -ne "" -and $finherit -eq $true) {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'TerminalServicesIP'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_termsrvinitialprogram $_.Value $_.Value
						if ($result -eq $true) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'TerminalServices InitialProgram Active'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", DLL: " + $_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Test-EventViewerMSC {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Event Viewer MSC")
	$paths = @(
		"Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer"
		"Registry::$($State.DriveTargets.Hklm)SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Event Viewer"
	)
	$suspiciousEventNames = @(
		"MicrosoftRedirectionProgram", "MicrosoftRedirectionProgramCommandLineParameters", "MicrosoftRedirectionURL"
	)
	$allowedValues = @(
		"", "http://go.microsoft.com/fwlink/events.asp"
	)

	foreach ($path in $paths) {
		if (-not( Test-Path -Path $path)) {
			continue
		}

		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if (-not ($_.Name -in $suspiciousEventNames -and $_.Value -notin $allowedValues)) {
				continue 
			}

			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($_.Name, $_.Value, "MSCHijack"), $true)) {
				continue
			}

			$State.WriteDetection([TrawlerDetection]::new(
					'Event Viewer MSC Hijack',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1574: Hijack Execution Flow",
					[PSCustomObject]@{
						KeyLocation = $path
						EntryName   = $_.Name
						LoadedValue = $_.Value
					}
				))
		}
	}
}

function Test-RDPStartupPrograms {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking RDP Startup Programs")
	$allowed_rdp_startups = @(
		"rdpclip"
	)
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Terminal Server\Wds\rdpwd"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'StartupPrograms' -and $_.Value -ne "") {
				$packages = $_.Value.Split(",")
				foreach ($package in $packages) {
					if ($package -notin $allowed_rdp_startups) {
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'RDPStartup'

						$pass = $false
						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_rdpstartup $package $package
							if ($result -eq $true) {
								$pass = $true
							}
						}
						if ($pass -eq $false) {
							$detection = [PSCustomObject]@{
								Name      = 'Non-Standard RDP Startup Program'
								Risk      = 'Medium'
								Source    = 'Registry'
								Technique = "T1574: Hijack Execution Flow"
								Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
							}
							Write-Detection $detection
						}
					}
				}
			}
		}
	}
}

<#
# Start T1574.007
#>

function Test-PATHHijacks {
    [CmdletBinding()]
    param (
        [Parameter()]
        [TrawlerState]
        $State
    )
    # Supports Dynamic Snapshotting
    # Mostly supports drive retargeting - assumed PATH is prefixed with C:
    # Data Stored at HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Environment
    # Can just collect from this key instead of actual PATH var
    $State.WriteMessage("Checking PATH Hijacks")
    $system32_path = "$env_homedrive\windows\system32"
    $system32_bins = Get-ChildItem -File -Path $system32_path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object Name
    $sys32_bins = New-Object -TypeName "System.Collections.ArrayList"

    foreach ($bin in $system32_bins) {
        $sys32_bins.Add($bin.Name) | Out-Null
    }
    $path_reg = "Registry::$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Control\Session Manager\Environment"
    if (Test-Path -Path $path_reg) {
        $items = Get-ItemProperty -Path $path_reg | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -eq "Path") {
                $path_entries = $_.Value
            }
        }
    }
    $path_entries = $path_entries.Split(";")
    $paths_before_sys32 = New-Object -TypeName "System.Collections.ArrayList"
    foreach ($path in $path_entries) {
        $path = $path.Replace("C:", $env_homedrive)
        if ($path -ne $system32_path) {
            $paths_before_sys32.Add($path) | Out-Null
        }
        else {
            break
        }
    }

    foreach ($path in $paths_before_sys32) {
        $path_bins = Get-ChildItem -File -Path $path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object *
        foreach ($bin in $path_bins) {
            if ($bin.Name -in $sys32_bins) {
                Write-SnapshotMessage -Key $bin.FullName -Value $bin.Name -Source 'PATHHijack'

                if ($loadsnapshot) {
                    $result = Assert-IsAllowed $allowlist_pathhijack $bin.FullName
                    if ($result) {
                        continue
                    }
                }
                $detection = [PSCustomObject]@{
                    Name      = 'Possible PATH Binary Hijack - same name as SYS32 binary in earlier PATH entry'
                    Risk      = 'Very High'
                    Source    = 'PATH'
                    Technique = "T1574.007: Hijack Execution Flow: Path Interception by PATH Environment Variable"
                    Meta      = "File: " + $bin.FullName + ", Creation Time: " + $bin.CreationTime + ", Last Write Time: " + $bin.LastWriteTime
                }
                #Write-Host $detection.Meta
                Write-Detection $detection
            }
        }

    }
}

<#
# Start T1574.009
#>

function Test-ServiceHijacks {
    [CmdletBinding()]
    param (
        [Parameter()]
        [TrawlerState]
        $State
    )
    $State.WriteMessage("Checking Un-Quoted Services")
    # Supports Drive Retargeting, assumes homedrive is C:
    #$services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
    $service_path = "$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Services"
    $service_list = New-Object -TypeName "System.Collections.ArrayList"
    if (Test-Path -Path "Registry::$service_path") {
        $items = Get-ChildItem -Path "Registry::$service_path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
        foreach ($item in $items) {
            $path = "Registry::" + $item.Name
            $data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSProvider
            if ($data.ImagePath -ne $null) {
                $service = [PSCustomObject]@{
                    Name     = $data.PSChildName
                    PathName = $data.ImagePath
                }
                $service.PathName = $service.PathName.Replace("\SystemRoot", "$env_assumedhomedrive\Windows")
                $service_list.Add($service) | Out-Null
            }
        }
    }
    foreach ($service in $service_list) {
        $service.PathName = ($service.PathName).Replace("C:", $env_homedrive)
        if ($service.PathName -match '".*"[\s]?.*') {
            # Skip Paths where the executable is contained in quotes
            continue
        }
        # Is there a space in the service path?
        if ($service.PathName.Contains(" ")) {
            $original_service_path = $service.PathName
            # Does the path contain a space before the exe?
            if ($original_service_path -match '.*\s.*\.exe.*') {
                $tmp_path = $original_service_path.Split(" ")
                $base_path = ""
                foreach ($path in $tmp_path) {
                    $base_path += $path
                    $test_path = $base_path + ".exe"
                    if (Test-Path $test_path) {
                        $detection = [PSCustomObject]@{
                            Name      = 'Possible Service Path Hijack via Unquoted Path'
                            Risk      = 'High'
                            Source    = 'Services'
                            Technique = "T1574.009: Create or Modify System Process: Windows Service"
                            Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName + ", Suspicious File: " + $test_path
                        }
                        Write-Detection $detection
                    }
                    $base_path += " "
                }
            }
        }
    }
}