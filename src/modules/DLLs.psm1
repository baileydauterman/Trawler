
function Test-AppCertDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking AppCert DLLs"
	$standard_appcert_dlls = @()
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Session Manager\AppCertDlls"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Value -notin $standard_appcert_dlls) {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppCertDLLs'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_appcertdlls $_.Name $_.Value
					if ($result -eq $true) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential Persistence via AppCertDLL Hijack'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1546.009: Event Triggered Execution: AppCert DLLs"
						Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}


function Test-AppInitDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking AppInit DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AppInit_DLLs' -and $_.Value -ne '') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppInitDLLs'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_appinitdlls $_.Name $_.Value
					if ($result -eq $true) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential AppInit DLL Persistence'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1546.010: Event Triggered Execution: AppInit DLLs"
						Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
	$path = "Registry::$regtarget_hklm`Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AppInit_DLLs' -and $_.Value -ne '') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'AppInitDLLs'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_appinitdlls $_.Name $_.Value
					if ($result -eq $true) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential AppInit DLL Persistence'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1546.010: Event Triggered Execution: AppInit DLLs"
						Meta      = "Key Location: HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}

}


function Test-AutoDialDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	Write-Message "Checking Autodial DLL"
	$path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Services\WinSock2\Parameters"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'AutodialDLL' -and $_.Value -ne 'C:\Windows\System32\rasadhlp.dll') {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Hijacking of Autodial DLL'
					Risk      = 'Very High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-HTMLHelpDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	Write-Message "Checking HTML Help (.chm) DLL"
	$basepath = "HKEY_CURRENT_USER\Software\Microsoft\HtmlHelp Author"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path "Registry::$path") {
			$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'location') {
					$detection = [PSCustomObject]@{
						Name      = 'Potential CHM DLL Hijack'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1546: Event Triggered Execution"
						Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Test-MSDTCDll {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
	Write-Message "Checking MSDTC DLL Hijack"
	$matches = @{
		"OracleOciLib"     = "oci.dll"
		"OracleOciLibPath" = "$env_assumedhomedrive\Windows\system32"
		"OracleSqlLib"     = "SQLLib80.dll"
		"OracleSqlLibPath" = "$env_assumedhomedrive\Windows\system32"
		"OracleXaLib"      = "xa80.dll"
		"OracleXaLibPath"  = "$env_assumedhomedrive\Windows\system32"
	}
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\MSDTC\MTxOCI"
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


function Test-NaturalLanguageDevelopmentDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking NaturalLanguageDevelopment DLLs"
	$path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Control\ContentIndex\Language"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.StemmerDLLPathOverride -ne $null -or $data.WBDLLPathOverride) {
				if ($data.StemmerDLLPathOverride -ne $null) {
					$dll = $data.StemmerDLLPathOverride
				}
				elseif ($data.WBDLLPathOverride -ne $null) {
					$dll = $data.WBDLLPathOverride
				}

				Write-SnapshotMessage -Key $item.Name -Value $dll -Source 'NLPDlls'

				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_nlpdlls $item.Name $dll
					if ($result) {
						continue
					}
				}
				$detection = [PSCustomObject]@{
					Name      = 'DLL Override on Natural Language Development Platform'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1112: Modify Registry"
					Meta      = "Registry Path: " + $item.Name + ", DLL: " + $dll
				}
				Write-Detection $detection
			}
		}
	}
}


function Test-TerminalServicesDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	Write-Message "Checking TerminalServices DLL"
	$path = "Registry::$regtarget_hklm`SYSTEM\CurrentControlSet\Services\TermService\Parameters"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ServiceDll' -and $_.Value -ne 'C:\Windows\System32\termsrv.dll') {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Hijacking of Terminal Services DLL'
					Risk      = 'Very High'
					Source    = 'Registry'
					Technique = "T1505.005: Server Software Component: Terminal Services DLL"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}


function Test-TrustProviderDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	Write-Message "Checking Trust Provider"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Dll' -and $_.Value -notin @("C:\Windows\System32\pwrship.dll", "C:\Windows\System32\WindowsPowerShell\v1.0\pwrshsip.dll")) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Hijacking of Trust Provider'
					Risk      = 'Very High'
					Source    = 'Registry'
					Technique = "T1553: Subvert Trust Controls"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
			if ($_.Name -eq 'FuncName' -and $_.Value -ne 'PsVerifyHash') {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Hijacking of Trust Provider'
					Risk      = 'Very High'
					Source    = 'Registry'
					Technique = "T1553: Subvert Trust Controls"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}


function Test-NetSHDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking NetSH DLLs"
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
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Netsh"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Value -notin $standard_netsh_dlls) {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'NetshDLLs'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_netshdlls $_.Name $_.Value
					if ($result -eq $true) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential Persistence via Netsh Helper DLL Hijack'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1546.007: Event Triggered Execution: Netsh Helper DLL"
						Meta      = "Key Location: HKLM\SOFTWARE\Microsoft\Netsh, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
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
	Write-Message "Checking PeerDistExtension DLL"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension"
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
	Write-Message "Checking InternetSettings DLL"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\LUI"
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
	Write-Message "Checking BID DLL"
	$paths = @(
		"Registry::$regtarget_hklm`Software\Microsoft\BidInterface\Loader"
		"Registry::$regtarget_hklm`software\Wow6432Node\Microsoft\BidInterface\Loader"

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
	Write-Message "Checking Windows Update Test"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Test"
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
	Write-Message "Checking MiniDumpAuxiliary DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls"
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


function Test-WinlogonHelperDLLs {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Winlogon Helper DLLs"
	$standard_winlogon_helper_dlls = @(
		"C:\Windows\System32\userinit.exe,"
		"explorer.exe"
		"sihost.exe"
		"ShellAppRuntime.exe"
		"mpnotify.exe"
	)
	$path = "Registry::$regtarget_hklm`Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -in 'Userinit', 'Shell', 'ShellInfrastructure', 'ShellAppRuntime', 'MPNotify' -and $_.Value -notin $standard_winlogon_helper_dlls) {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'WinlogonHelpers'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_winlogonhelpers $_.Value $_.Value
					if ($result) {
						$pass = $true
					}
				}
				if ($pass -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential WinLogon Helper Persistence'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1547.004: Boot or Logon Autostart Execution: Winlogon Helper DLL"
						Meta      = "Key Location: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
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
	Write-Message "Checking PrintMonitor DLLs"
	$standard_print_monitors = @(
		"APMon.dll",
		"AppMon.dll",
		"FXSMON.dll",
		"localspl.dll",
		"tcpmon.dll",
		"usbmon.dll",
		"WSDMon.dll" # Server 2016
	)
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Print\Monitors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.Driver -ne $null) {
				Write-SnapshotMessage -Key $item.Name -Value $data.Driver -Source 'PrintMonitors'

				if ($loadsnapshot) {
					$detection = [PSCustomObject]@{
						Name      = 'Allowlist Mismatch: Non-Standard Print Monitor DLL'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1112: Modify Registry"
						Meta      = "Registry Path: " + $item.Name + ", System32 DLL: " + $data.Driver
					}
					$result = Assert-IsAllowed $allowtable_printmonitors $item.Name $data.Driver $detection
					if ($result) {
						continue
					}
				}
				if ($data.Driver -notin $standard_print_monitors) {
					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Print Monitor DLL'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1112: Modify Registry"
						Meta      = "Registry Path: " + $item.Name + ", System32 DLL: " + $data.Driver
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Test-DNSServerLevelPluginDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking DNSServerLevelPlugin DLL"
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Services\DNS\Parameters"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ServerLevelPluginDll' -and $_.Value -ne '""') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'DNSPlugin'

				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_dnsplugin $_.Value $_.Value
					if ($result -eq $true) {
						return
					}
				}
				$detection = [PSCustomObject]@{
					Name      = 'Review: DNS ServerLevelPluginDLL is active'
					Risk      = 'Medium'
					Source    = 'Registry'
					Technique = "T1055.001: Process Injection: Dynamic-link Library Injection"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", DLL: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-TimeProviderDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Time Provider DLLs"
	$standard_timeprovider_dll = @(
		"$env:homedrive\Windows\System32\w32time.dll",
		"$env:homedrive\Windows\System32\vmictimeprovider.dll"
	)
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Services\W32Time\TimeProviders"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.DllName -ne $null) {
				if ($standard_timeprovider_dll -notcontains $data.DllName) {
					Write-SnapshotMessage -Key $item.Name -Value $data.DllName -Source 'TimeProviders'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_timeproviders $data.DllName $data.DllName
						if ($result -eq $true) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Non-Standard Time Providers DLL'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1547.003: Boot or Logon Autostart Execution: Time Providers"
							Meta      = "Registry Path: " + $item.Name + ", DLL: " + $data.DllName
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Test-PrintProcessorDLLs {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking PrintProcessor DLLs"
	$standard_print_processors = @(
		"winprint.dll"
	)
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Print\Environments\Windows x64\Print Processors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.Driver -ne $null) {
				if ($loadsnapshot) {
					$detection = [PSCustomObject]@{
						Name      = 'Allowlist Mismatch: Non-Standard Print Processor DLL'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
						Meta      = "Registry Path: " + $item.Name + ", DLL: " + $data.Driver
					}
					$result = Assert-IsAllowed $allowtable_printprocessors $item.Name $data.Driver $detection
					if ($result) {
						continue
					}
				}
				if ($standard_print_processors -notcontains $data.Driver) {
					Write-SnapshotMessage -Key $item.Name -Value $data.Driver -Source 'PrintProcessors'

					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Print Processor DLL'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
						Meta      = "Registry Path: " + $item.Name + ", DLL: " + $data.Driver
					}
					Write-Detection $detection
				}
			}
		}
	}
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Print\Environments\Windows x64\Print Processors"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.Driver -ne $null) {
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowtable_printprocessors $item.Name $data.Driver
					if ($result) {
						continue
					}
				}
				if ($standard_print_processors -notcontains $data.Driver) {
					Write-SnapshotMessage -Key $item.Name -Value $data.Driver -Source 'PrintProcessors'

					$detection = [PSCustomObject]@{
						Name      = 'Non-Standard Print Processor DLL'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1547.012: Boot or Logon Autostart Execution: Print Processors"
						Meta      = "Registry Path: " + $item.Name + ", DLL: " + $data.Driver
					}
					Write-Detection $detection
				}
			}
		}
	}
}