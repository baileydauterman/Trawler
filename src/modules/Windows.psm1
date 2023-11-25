function Test-EventViewerMSC {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Event Viewer MSC"
	$paths = @(
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Event Viewer"
		"Registry::$regtarget_hklm`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Event Viewer"
	)
	foreach ($path in $paths) {
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -in "MicrosoftRedirectionProgram", "MicrosoftRedirectionProgramCommandLineParameters", "MicrosoftRedirectionURL" -and $_.Value -notin "", "http://go.microsoft.com/fwlink/events.asp") {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'MSCHijack'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_MSCHijack $_.Name $_.Value
						if ($result) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Event Viewer MSC Hijack'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1574: Hijack Execution Flow"
							Meta      = "Key Location: $path, Entry Name: " + $_.Name + " Loaded Value: " + $_.Value
						}
						Write-Detection $detection
					}
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
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Microsoft TelemetryController"
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
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.Command -ne $null) {
				if ($data.Command -notin $allowed_telemetry_commands) {
					Write-SnapshotMessage -Key $item.Name -Value $data.Command -Source 'TelemetryCommands'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_telemetry $item.Name $data.Command
						if ($result) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Non-Standard Microsoft Telemetry Command'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1112: Modify Registry"
							Meta      = "Registry Path: " + $item.Name + ", Command: " + $data.Command
						}
						Write-Detection $detection
					}
				}
			}
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
	Write-Message "Checking RemoteUAC Setting"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'LocalAccountTokenFilterPolicy') {
				Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'RemoteUAC'

				if ($loadsnapshot) {
					$detection = [PSCustomObject]@{
						Name      = 'Allowlist Mismatch: UAC Remote Sessions'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1112: Modify Registry"
						Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					$result = Assert-IsAllowed $allowtable_remoteuac $_.Name $_.Value $detection
					if ($result -eq $true) {
						return
					}
				}
			}
			if ($_.Name -eq 'LocalAccountTokenFilterPolicy' -and $_.Value -eq 1) {
				$detection = [PSCustomObject]@{
					Name      = 'UAC Disabled for Remote Sessions'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1112: Modify Registry"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
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
	Write-Message "Checking Explorer Helper exes"
	$paths = @(
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\BackupPath"
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\cleanuppath"
		"Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath"
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

function Test-ScreenSaverEXE {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	Write-Message "Checking ScreenSaver exe"
	$basepath = "Registry::HKEY_CURRENT_USER\Control Panel\Desktop"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq "SCRNSAVE.exe") {
					$detection = [PSCustomObject]@{
						Name      = 'Potential Persistence via ScreenSaver Executable Hijack'
						Risk      = 'High'
						Source    = 'Registry'
						Technique = "T1546.002: Event Triggered Execution: Screensaver"
						Meta      = "Key Location: HKCU\Control Panel\Desktop, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}
function Test-Process-Modules {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Does not support Drive Retargeting
	if ($drivechange) {
		Write-Message "Skipping Phantom DLLs - No Drive Retargeting"
		return
	}
	Write-Message "Checking 'Phantom' DLLs"
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
	Write-Message "Checking Unsigned Files"
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

function Test-SuspiciousCertificates {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Can maybe support drive retargeting
	if ($drivechange) {
		Write-Message "Skipping Certificate Analysis - No Drive Retargeting [yet]"
		return
	}
	# https://www.michev.info/blog/post/1435/windows-certificate-stores#:~:text=Under%20file%3A%5C%25APPDATA%25%5C,find%20all%20your%20personal%20certificates.
	Write-Message "Checking Certificates"
	$certs = Get-ChildItem -path cert:\ -Recurse | Select-Object *
	# PSPath,DnsNameList,SendAsTrustedIssuer,PolicyId,Archived,FriendlyName,IssuerName,NotAfter,NotBefore,HasPrivateKey,SerialNumber,SubjectName,Version,Issuer,Subject
	$wellknown_ca = @(
		"DigiCert.*",
		"GlobalSign.*",
		"Comodo.*",
		"VeriSign.*",
		"Microsoft Corporation.*",
		"Go Daddy.*"
		"SecureTrust.*"
		"Entrust.*"
		"Microsoft.*"
		"USERTrust RSA Certification Authority"
		"Blizzard.*"
		"Hellenic Academic and Research Institutions.*"
		"Starfield.*"
		"T-TeleSec GlobalRoot.*"
		"QuoVadis.*"
		"ISRG Root.*"
		"Baltimore CyberTrust.*"
		"Security Communication Root.*"
		"AAA Certificate Services.*"
		"thawte Primary Root.*"
		"SECOM Trust.*"
		"Certum Trusted Network.*"
		"SSL\.com Root Certification.*"
		"Amazon Root.*"
		'"VeriSign.*'
		"VeriSign Trust Network.*"
		"Microsoft Trust Network"
		"Thawte Timestamping CA"
		"GeoTrust Primary Certification Authority.*"
		"Certum CA"
		"XBL Client IPsec Issuing CA"
		"Network Solutions Certificate Authority"
		"D-TRUST Root Class 3 CA.*"
		"Hotspot 2.0 Trust Root CA.*"
	)
	$date = Get-Date
	foreach ($cert in $certs) {
		# Skip current object if it is a container of a cert rather than a certificate directly
		if ($cert.PSIsContainer) {
			continue
		}
		if ($cert.PSPath.Contains("\Root\") -or $cert.PSPath.Contains("\AuthRoot\") -or $cert.PSPath.Contains("\CertificateAuthority\")) {
			$trusted_cert = $true
		}
		else {
			continue
		}

		$cn_pattern = ".*CN=(.*?),.*"
		$cn_pattern_2 = "CN=(.*)"
		$ou_pattern = ".*O=(.*?),.*"
		$ou_pattern_2 = ".*O=(.*?)"

		$cn_match = [regex]::Matches($cert.Issuer, $cn_pattern).Groups.Captures.Value
		#Write-Host $cert.Issuer
		if ($cn_match -ne $null) {
			#Write-Host $cn_match[1]
		}
		else {
			$cn_match = [regex]::Matches($cert.Issuer, $cn_pattern_2).Groups.Captures.Value
			if ($cn_match -ne $null) {
				#Write-Host $cn_match[1]
			}
			else {
				$cn_match = [regex]::Matches($cert.Issuer, $ou_pattern).Groups.Captures.Value
				#Write-Host $cn_match[1]
				if ($cn_match -eq $null) {
					$cn_match = [regex]::Matches($cert.Issuer, $ou_pattern_2).Groups.Captures.Value
				}
			}
		}

		$signer = $cn_match[1]
		$diff = New-TimeSpan -Start $date -End $cert.NotAfter
		$cert_verification_status = Test-Certificate -Cert $cert.PSPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

		foreach ($ca in $wellknown_ca) {
			if ($signer -match $ca) {
				#Write-Host "Comparing:"+$signer+" to"+$ca
				$valid_signer = $true
				break
			}
			else {
				$valid_signer = $false
			}
		}

		Write-SnapshotMessage -Key $cert.Issuer -Value $cert.Subject -Source 'Certificates'

		if ($loadsnapshot) {
			$detection = [PSCustomObject]@{
				Name      = 'Allowlist Mismatch: Certificate'
				Risk      = 'Medium'
				Source    = 'Certificates'
				Technique = "T1553: Subvert Trust Controls: Install Root Certificate"
				Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
			}
			$result = Assert-IsAllowed $allowtable_certificates $cert.Issuer $cert.Subject $detection
			if ($result) {
				continue
			}
		}

		# Valid Cert, Unknown Signer, Valid in Date, Contains Root/AuthRoot/CertificateAuthority
		if ($cert_verification_status -eq $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			$detection = [PSCustomObject]@{
				Name      = 'Valid Root or CA Certificate Issued by Non-Standard Authority'
				Risk      = 'Low'
				Source    = 'Certificates'
				Technique = "T1553: Subvert Trust Controls: Install Root Certificate"
				Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
			}
			Write-Detection $detection
			#Write-Host $detection.Meta
		}
		if ($cert_verification_status -ne $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			$detection = [PSCustomObject]@{
				Name      = 'Invalid Root or CA Certificate Issued by Non-Standard Authority'
				Risk      = 'Low'
				Source    = 'Certificates'
				Technique = "T1553: Subvert Trust Controls: Install Root Certificate"
				Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
			}
			Write-Detection $detection
			#Write-Host $detection.Meta
		}


		#$cert.SubjectName.Name
		# TODO - Maybe remove valid_signer from this later on if we care that much about 'valid' signer certs which failed validation
		if ($cert_verification_status -ne $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			# Invalid Certs that are still within valid range
			if ($cert.PSPath.Contains("\Root\")) {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Trusted Root Certificate Failed Validation'
					Risk      = 'Medium'
					Source    = 'Certificates'
					Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				Write-Detection $detection
				#Write-Host $detection.Meta
			}
			elseif ($cert.PSPath.Contains("\AuthRoot\")) {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Third-Party Root Certificate Failed Validation'
					Risk      = 'Low'
					Source    = 'Certificates'
					Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				Write-Detection $detection
				#Write-Host $detection.Meta
			}
			elseif ($cert.PSPath.Contains("\CertificateAuthority\")) {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Intermediary Certificate Failed Validation'
					Risk      = 'Low'
					Source    = 'Certificates'
					Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				Write-Detection $detection
				#Write-Host $detection.Meta
			}
			else {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Certificate Failed Validation'
					Risk      = 'Very Low'
					Source    = 'Certificates'
					Technique = "T1553: Subvert Trust Controls"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				Write-Detection $detection
				#Write-Host $detection.Meta
			}
		}
		elseif ($cert_verification_status -and $diff.Hours -ge 0) {
			# Validated Certs that are still valid
		}
	}
}

function Test-GPOScripts {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking GPO Scripts"
	$base_key = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts"
	$script_paths = New-Object -TypeName "System.Collections.ArrayList"
	$homedrive = $env_homedrive
	$paths = @(
		"$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\psscripts.ini",
		"$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\scripts.ini",
		"$homedrive\Windows\System32\GroupPolicy\User\Scripts\psscripts.ini",
		"$homedrive\Windows\System32\GroupPolicy\User\Scripts\scripts.ini"
	)
	$path_lookup = @{
		Startup  = "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\Startup\"
		Shutdown = "$homedrive\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown\"
		Logoff   = "$homedrive\Windows\System32\GroupPolicy\User\Scripts\Logoff\"
		Logon    = "$homedrive\Windows\System32\GroupPolicy\User\Scripts\Logon\"
	}

	foreach ($path in $paths) {
		# Skip non-existent files
		if ((Test-Path $path) -eq $false) {
			return
		}
		$content = Get-Content $path
		$script_type = ""
		foreach ($line in $content) {
			if ($line.Trim() -eq "") {
				continue
			}
			if ($line -eq "[Shutdown]") {
				$script_type = "Shutdown"
			}
			elseif ($line -eq "[Startup]") {
				$script_type = "Startup"
			}
			elseif ($line -eq "[Logon]") {
				$script_type = "Logon"
			}
			elseif ($line -eq "[Logoff]") {
				$script_type = "Logoff"
			}
			elseif ($line -match "\d{1,9}CmdLine=") {
				$cmdline = $line.Split("=", 2)[1]
			}
			elseif ($line -match "\d{1,9}Parameters=") {
				$params = $line.Split("=", 2)[1]
			}
			if ($params -ne $null) {
				# Last line in each script descriptor is the Parameters
				if ($script_type -eq "Shutdown" -or $script_type -eq "Startup") {
					$desc = "Machine $script_type Script"
				}
				elseif ($script_type -eq "Logon" -or $script_paths -eq "Logoff") {
					$desc = "User $script_type Script"
				}

				$script_location = $cmdline
				if ($cmdline -notmatch "[A-Za-z]{1}:\\.*") {
					$script_location = $path_lookup[$script_type] + $cmdline
				}

				Write-SnapshotMessage -Key $script_location -Value $script_location -Source 'GPOScripts'

				$pass = $false
				if ($loadsnapshot) {
					$result = Assert-IsAllowed $allowlist_gposcripts $script_location $script_location
					if ($result) {
						$cmdline = $null
						$params = $null
						continue
					}
				}
				# TODO - Figure out ERROR
				$script_content_detection = $false
				try {
					$script_content = Get-Content $script_location
					foreach ($line_ in $script_content) {
						if ($line_ -match $suspicious_terms -and $script_content_detection -eq $false) {
							$detection = [PSCustomObject]@{
								Name      = 'Suspicious Content in ' + $desc
								Risk      = 'High'
								Source    = 'Windows GPO Scripts'
								Technique = "T1037: Boot or Logon Initialization Scripts"
								Meta      = "File: " + $script_location + ", Arguments: " + $params + ", Suspicious Line: " + $line_
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
						Name      = 'Review: ' + $desc
						Risk      = 'Medium'
						Source    = 'Windows GPO Scripts'
						Technique = "T1037: Boot or Logon Initialization Scripts"
						Meta      = "File: " + $script_location + ", Arguments: " + $params
					}
					Write-Detection $detection
				}
				$cmdline = $null
				$params = $null
			}

		}
	}

}

function Test-BITS {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Maybe with Drive Retargeting
	# C:\ProgramData\Microsoft\Network\Downloader
	# https://www.giac.org/paper/gcih/28198/bits-forensics/130713#:~:text=These%20files%20are%20named%20%E2%80%9Cqmgr0,Microsoft%5CNetwork%5CDownloader%E2%80%9D.
	if ($drivechange) {
		Write-Message "Skipping BITS Analysis - No Drive Retargeting [yet]"
		return
	}
	Write-Message "Checking BITS Jobs"
	$bits = Get-BitsTransfer -AllUsers | Select-Object *
	foreach ($item in $bits) {
		if ($item.NotifyCmdLine -ne $null) {
			$cmd = [string]$item.NotifyCmdLine
		}
		else {
			$cmd = ''
		}
        
		Write-SnapshotMessage -Key $item.DisplayName -Value $cmd -Source 'BITS'
		
		if ($loadsnapshot) {
			$detection = [PSCustomObject]@{
				Name      = 'Allowlist Mismatch:  BITS Job'
				Risk      = 'Medium'
				Source    = 'BITS'
				Technique = "T1197: BITS Jobs"
				Meta      = "Item Name: " + $item.DisplayName + ", TransferType: " + $item.TransferType + ", Job State: " + $item.JobState + ", User: " + $item.OwnerAccount + ", Command: " + $cmd
			}
			$result = Assert-IsAllowed $allowtable_bits $item.DisplayName $cmd $detection
			if ($result) {
				continue
			}
		}
		$detection = [PSCustomObject]@{
			Name      = 'BITS Item Review'
			Risk      = 'Low'
			Source    = 'BITS'
			Technique = "T1197: BITS Jobs"
			Meta      = "Item Name: " + $item.DisplayName + ", TransferType: " + $item.TransferType + ", Job State: " + $item.JobState + ", User: " + $item.OwnerAccount + ", Command: " + $cmd
		}
		Write-Detection $detection
	}
}

function Test-ModifiedWindowsAccessibilityFeature {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# TODO - Consider allow-listing here
	# Supports Drive Retargeting
	Write-Message "Checking Accessibility Binaries"
	$files_to_check = @(
		"$env_homedrive\Program Files\Common Files\microsoft shared\ink\HID.dll"
		"$env_homedrive\Windows\System32\AtBroker.exe",
		"$env_homedrive\Windows\System32\DisplaySwitch.exe",
		"$env_homedrive\Windows\System32\Magnify.exe",
		"$env_homedrive\Windows\System32\Narrator.exe",
		"$env_homedrive\Windows\System32\osk.exe",
		"$env_homedrive\Windows\System32\sethc.exe",
		"$env_homedrive\Windows\System32\utilman.exe"
	)
	foreach ($file in $files_to_check) { 
		$fdata = Get-Item $file -ErrorAction SilentlyContinue | Select-Object CreationTime, LastWriteTime
		if ($fdata.CreationTime -ne $null) {
			if ($fdata.CreationTime.ToString() -ne $fdata.LastWriteTime.ToString()) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential modification of Windows Accessibility Feature'
					Risk      = 'High'
					Source    = 'Windows'
					Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
					Meta      = "File: " + $file + ", Created: " + $fdata.CreationTime + ", Modified: " + $fdata.LastWriteTime
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-PowerShellProfiles {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
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
	Write-Message "Checking PowerShell Profiles"
	if ($drivechange) {
		# TODO - Investigate whether these paths can be retrieved from the HKLM HIVE dynamically
		$alluserallhost = "$env_homedrive\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
		$allusercurrenthost = "$env_homedrive\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1"
	}
 else {
		$PROFILE | Select-Object AllUsersAllHosts, AllUsersCurrentHost, CurrentUserAllHosts, CurrentUserCurrentHost | Out-Null
		$alluserallhost = $PROFILE.AllUsersAllHosts
		$allusercurrenthost = $PROFILE.AllUsersCurrentHost
	}

	if (Test-Path $alluserallhost) {
		$detection = [PSCustomObject]@{
			Name      = 'Review: Global Custom PowerShell Profile'
			Risk      = 'Medium'
			Source    = 'PowerShell'
			Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
			Meta      = "Profile: " + $PROFILE.AllUsersAllHosts
		}
		Write-Detection $detection
	}
	if (Test-Path $allusercurrenthost) {
		$detection = [PSCustomObject]@{
			Name      = 'Review: Global Custom PowerShell Profile'
			Risk      = 'Medium'
			Source    = 'PowerShell'
			Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
			Meta      = "Profile: " + $PROFILE.AllUsersCurrentHost
		}
		Write-Detection $detection
	}

	$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object Name
	foreach ($name in $profile_names) {
		$path1 = "$env_homedrive\Users\$name\Documents\WindowsPowerShell\profile.ps1"
		$path2 = "$env_homedrive\Users\$name\Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1"
		$path3 = "$env_homedrive\Users\$name\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
		if (Test-Path $path1) {
			$detection = [PSCustomObject]@{
				Name      = 'Review: Custom PowerShell Profile'
				Risk      = 'Medium'
				Source    = 'PowerShell'
				Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
				Meta      = "Profile: " + $path1
			}
			Write-Detection $detection
		}
		if (Test-Path $path2) {
			$detection = [PSCustomObject]@{
				Name      = 'Review: Custom PowerShell Profile'
				Risk      = 'Medium'
				Source    = 'PowerShell'
				Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
				Meta      = "Profile: " + $path2
			}
			Write-Detection $detection
		}
		if (Test-Path $path3) {
			$detection = [PSCustomObject]@{
				Name      = 'Review: Custom PowerShell Profile'
				Risk      = 'Medium'
				Source    = 'PowerShell'
				Technique = "T1546.013: Event Triggered Execution: PowerShell Profile"
				Meta      = "Profile: " + $path3
			}
			Write-Detection $detection
		}
	}
}



function Test-RegistryChecks {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
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
							$detection = [PSCustomObject]@{
								Name      = 'Potential COM Hijack'
								Risk      = 'High'
								Source    = 'Registry'
								Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
								Meta      = "Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
							}
							#Write-Detection $detection
							# This is now handled by Test-COM-Hijacks along with HKLM and HKCR checks (which should be identical)
						}
					}
				}
			}
		}
	}


}

function Test-Users {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Can possibly support drive retargeting by reading SAM/SYSTEM Hives if intact
	# https://habr.com/en/articles/441410/
	if ($drivechange) {
		Write-Message "Skipping User Analysis - No Drive Retargeting [yet]"
		return
	}

	Write-Message "Checking Local Administrators"

	# TODO - Catch error with outdated powershell versions that do not support Get-LocalGroupMember and use alternative gather mechanism
	# Find all local administrators and their last logon time as well as if they are enabled.
	$local_admins = Get-LocalGroupMember -Group "Administrators" | Select-Object *

	foreach ($admin in $local_admins) {
		$admin_user = Get-LocalUser -SID $admin.SID | Select-Object AccountExpires, Description, Enabled, FullName, PasswordExpires, UserMayChangePassword, PasswordLastSet, LastLogon, Name, SID, PrincipalSource

		Write-SnapshotMessage -Key $admin.name -Value $admin.name -Source "Users"

		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_users $admin.nam $admin.name)) {
			continue
		}

		$detection = [PSCustomObject]@{
			Name      = 'Local Administrator Account'
			Risk      = 'Medium'
			Source    = 'Users'
			Technique = "T1136: Create Account"
			Meta      = "Name: " + $admin.Name + ", Last Logon: " + $admin_user.LastLogon + ", Enabled: " + $admin_user.Enabled
		}
		Write-Detection $detection
	}
    
}

function Test-Processes {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Does not support drive retargeting
	# TODO - Check for processes spawned from netsh.dll
	if ($drivechange) {
		Write-Message "Skipping Process Analysis - No Drive Retargeting"
		return
	}

	Write-Message "Checking Running Processes"
	$processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName, CreationDate, CommandLine, ExecutablePath, ParentProcessId, ProcessId
	foreach ($process in $processes) {
		Write-SnapshotMessage -Key $process.ProcessName -Value $process.ExecutablePath -Source "Processes"

		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_process_exes $process.ProcessName $process.ExecutablePath)) {
			continue
		}

		ForEach ($term in $rat_terms) {
			if ($process.CommandLine -match ".*$term.*") {
				$detection = [PSCustomObject]@{
					Name      = 'Running Process has known-RAT Keyword'
					Risk      = 'Medium'
					Source    = 'Processes'
					Technique = "T1059: Command and Scripting Interpreter"
					Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath + ", RAT Keyword: " + $term
				}
				Write-Detection $detection
			}
		}
		if ($process.CommandLine -match $ipv4_pattern -or $process.CommandLine -match $ipv6_pattern) {
			$detection = [PSCustomObject]@{
				Name      = 'IP Address Pattern detected in Process CommandLine'
				Risk      = 'Medium'
				Source    = 'Processes'
				Technique = "T1059: Command and Scripting Interpreter"
				Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath
			}
			Write-Detection $detection
		}
		# TODO - Determine if this should be changed to implement allow-listing through a set boolean or stay as-is
		foreach ($path in $suspicious_process_paths) {
			if ($process.ExecutablePath -match $path) {
				$detection = [PSCustomObject]@{
					Name      = 'Suspicious Executable Path on Running Process'
					Risk      = 'High'
					Source    = 'Processes'
					Technique = "T1059: Command and Scripting Interpreter"
					Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath
				}
				Write-Detection $detection
			}
		}

	}
}

function Test-WMIConsumers {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Drive Retargeting..maybe
	# https://netsecninja.github.io/dfir-notes/wmi-forensics/
	# https://github.com/davidpany/WMI_Forensics
	# https://github.com/mandiant/flare-wmi/blob/master/WMIParser/WMIParser/ActiveScriptConsumer.cpp
	# This would require building a binary parser in PowerShell..difficult.
	if ($drivechange) {
		Write-Message "Skipping WMI Analysis - No Drive Retargeting [yet]"
		return
	}
	Write-Message "Checking WMI Consumers"
	$consumers = Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object *

	foreach ($consumer in $consumers) {
		if ($loadsnapshot) {
			if ($consumer.CommandLineTemplate -ne $null) {
				$val_ = $consumer.CommandLineTemplate
			}
			elseif ($consumer.ScriptFileName -ne $null) {
				$val_ = $consumer.ScriptFileName
			}
			$detection = [PSCustomObject]@{
				Name      = 'Allowlist Mismatch:  WMI Consumer'
				Risk      = 'Medium'
				Source    = 'Services'
				Technique = "T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription"
				Meta      = "Consumer Name: " + $consumer.Name + ", Consumer Value: " + $val_
			}
			$result = Assert-IsAllowed $allowtable_wmi_consumers $consumer.Name $val_ $detection
			if ($result) {
				continue
			}
		}
		if ($consumer.ScriptingEngine -ne $null) {
			Write-SnapshotMessage -Key $consumer.Name -Value $consumer.ScriptFileName -Source 'WMI Consumers'

			$detection = [PSCustomObject]@{
				Name      = 'WMI ActiveScript Consumer'
				Risk      = 'High'
				Source    = 'WMI'
				Technique = "T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription"
				Meta      = "Consumer Name: " + $consumer.Name + ", Script Name: " + $consumer.ScriptFileName + ", Script Text: " + $consumer.ScriptText
			}
			Write-Detection $detection
		}
		if ($consumer.CommandLineTemplate -ne $null) {
			Write-SnapshotMessage -Key $consumer.Name -Value $consumer.CommandLineTemplate -Source 'WMI Consumers'
			
			$detection = [PSCustomObject]@{
				Name      = 'WMI CommandLine Consumer'
				Risk      = 'High'
				Source    = 'WMI'
				Technique = "T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription"
				Meta      = "Consumer Name: " + $consumer.Name + ", Executable Path: " + $consumer.ExecutablePath + ", CommandLine Template: " + $consumer.CommandLineTemplate
			}
			Write-Detection $detection
		}
	}
}
function Test-LNK {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# TODO - Maybe, Snapshots
	# Supports Drive Retargeting
	Write-Message "Checking LNK Targets"
	$current_date = Get-Date
	$WScript = New-Object -ComObject WScript.Shell
	$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
	foreach ($user in $profile_names) {
		$path = "$env_homedrive\Users\" + $user.Name + "\AppData\Roaming\Microsoft\Windows\Recent"
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
						Risk      = 'High'
						Source    = 'LNK'
						Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
						Meta      = "LNK File: " + $item.FullName + ", LNK Target: " + $lnk_target + ", Last Write Time: " + $item.LastWriteTime
					}
					Write-Detection $detection
				}
				if ($lnk_target -match $suspicious_terms) {
					$detection = [PSCustomObject]@{
						Name      = 'LNK Target contains suspicious key-term'
						Risk      = 'High'
						Source    = 'LNK'
						Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
						Meta      = "LNK File: " + $item.FullName + ", LNK Target: " + $lnk_target + ", Last Write Time: " + $item.LastWriteTime
					}
					Write-Detection $detection
				}
				if ($lnk_target -match ".*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*\.(csv|pdf|xlsx|doc|ppt|txt|jpeg|png|gif|exe|dll|ps1|webp|svg|zip|xls).*") {
					$detection = [PSCustomObject]@{
						Name      = 'LNK Target contains multiple file extensions'
						Risk      = 'Medium'
						Source    = 'LNK'
						Technique = "T1547.009: Boot or Logon Autostart Execution: Shortcut Modification"
						Meta      = "LNK File: " + $item.FullName + ", LNK Target: " + $lnk_target + ", Last Write Time: " + $item.LastWriteTime
					}
					Write-Detection $detection
				}

			}
		}
	}
}

function Test-TerminalProfiles {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	# TODO - Snapshot/Allowlist specific exes
	Write-Message "Checking Terminal Profiles"
	$profile_names = Get-ChildItem "$env_homedrive\Users" -Attributes Directory | Select-Object *
	$base_path = "$env_homedrive\Users\_USER_\AppData\Local\Packages\"
	foreach ($user in $profile_names) {
		$new_path = $base_path.replace("_USER_", $user.Name)
		$new_path += "Microsoft.WindowsTerminal*"
		$terminalDirs = Get-ChildItem $new_path -ErrorAction SilentlyContinue
		foreach ($dir in $terminalDirs) {
			if (Test-Path "$dir\LocalState\settings.json") {
				$settings_data = Get-Content -Raw "$dir\LocalState\settings.json" | ConvertFrom-Json
				if ($settings_data.startOnUserLogin -eq $null -or $settings_data.startOnUserLogin -ne $true) {
					continue
				}
				$defaultGUID = $settings_data.defaultProfile
				foreach ($profile_list in $settings_data.profiles) {
					foreach ($profile in $profile_list.List) {
						if ($profile.guid -eq $defaultGUID) {
							if ($profile.commandline) {
								$exe = $profile.commandline
							}
							else {
								$exe = $profile.name
							}
							$detection = [PSCustomObject]@{
								Name      = 'Windows Terminal launching command on login'
								Risk      = 'Medium'
								Source    = 'Terminal'
								Technique = "T1037: Boot or Logon Initialization Scripts"
								Meta      = "File: $dir\LocalState\settings.json, Command: " + $exe
							}
							Write-Detection $detection
						}
					}
				}
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
	Write-Message "Checking ErrorHandler.cmd"
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
	Write-Message "Checking Known Managed Debuggers"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\KnownManagedDebuggingDlls"
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
	Write-Message "Checking WOW64 Compatibility DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Wow64\x86"
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

function Test-ActiveSetup {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Active Setup Stubs"
	# T1547.014 - Boot or Logon Autostart Execution: Active Setup
	$standard_stubpaths = @(
		"/UserInstall",
		'"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', # Server 2016
		"$env_assumedhomedrive\Windows\System32\ie4uinit.exe -UserConfig", # 10
		"$env_assumedhomedrive\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install", # 10
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', # Server 2019
		'"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', # Server 2019
		"$env_assumedhomedrive\Windows\System32\unregmp2.exe /FirstLogon", # 10
		"$env_assumedhomedrive\Windows\System32\unregmp2.exe /ShowWMP", # 10
		"$env_assumedhomedrive\Windows\System32\ie4uinit.exe -EnableTLS",
		"$env_assumedhomedrive\Windows\System32\ie4uinit.exe -DisableSSL3"
		"U"
		"regsvr32.exe /s /n /i:U shell32.dll"
		"$env_assumedhomedrive\Windows\system32\regsvr32.exe /s /n /i:/UserInstall C:\Windows\system32\themeui.dll"
		"$env_assumedhomedrive\Windows\system32\unregmp2.exe /FirstLogon /Shortcuts /RegBrowsers /ResetMUI"
	)
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Active Setup\Installed Components"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.StubPath -ne $null) {
				if ($standard_stubpaths -notcontains $data.StubPath -and $data.StubPath -notmatch ".*(\\Program Files\\Google\\Chrome\\Application\\.*chrmstp.exe|Microsoft\\Edge\\Application\\.*\\Installer\\setup.exe).*") {
					Write-SnapshotMessage -Key $item.Name -Value $data.StubPath -Source 'ActiveSetup'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_activesetup $item.Name $data.StubPath
						if ($result) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Non-Standard StubPath Executed on User Logon'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1547.014: Boot or Logon Autostart Execution: Active Setup"
							Meta      = "Registry Path: " + $item.Name + ", StubPath: " + $data.StubPath
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Test-UninstallStrings {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking Uninstall Strings"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			#allowtable_uninstallstrings
			if ($data.UninstallString -ne $null) {
				if ($data.UninstallString -match $suspicious_terms) {
					Write-SnapshotMessage -Key $item.Name -Value $data.UninstallString -Source 'UninstallString'

					$pass = $false
					if ($loadsnapshot) {
						$detection = [PSCustomObject]@{
							Name      = 'Allowlist Mismatch: Uninstall String with Suspicious Keywords'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Application: " + $item.Name + ", Uninstall String: " + $data.UninstallString
						}
						$result = Assert-IsAllowed $allowtable_uninstallstrings $item.Name $data.UninstallString $detection
						if ($result) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Uninstall String with Suspicious Keywords'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Application: " + $item.Name + ", Uninstall String: " + $data.UninstallString
						}
						Write-Detection $detection
					}
				}
			}
			if ($data.QuietUninstallString -ne $null) {
				if ($data.QuietUninstallString -match $suspicious_terms) {
					Write-SnapshotMessage -Key $item.Name -Value $data.QuietUninstallString -Source 'QuietUninstallString'

					$pass = $false
					if ($loadsnapshot) {
						$detection = [PSCustomObject]@{
							Name      = 'Allowlist Mismatch: Uninstall String with Suspicious Keywords'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Application: " + $item.Name + ", Uninstall String: " + $data.QuietUninstallString
						}
						$result = Assert-IsAllowed $allowtable_quietuninstallstrings $item.Name $data.QuietUninstallString $detection
						if ($result) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'Uninstall String with Suspicious Keywords'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Application: " + $item.Name + ", Uninstall String: " + $data.QuietUninstallString
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}

function Test-PolicyManager {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking PolicyManager DLLs"
	$allow_listed_values = @(
		"%SYSTEMROOT%\system32\PolicyManagerPrecheck.dll"
		"%SYSTEMROOT%\system32\hascsp.dll"
	)
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\PolicyManager\default"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$items_ = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			foreach ($subkey in $items_) {
				$subpath = "Registry::" + $subkey.Name
				$data = Get-ItemProperty -Path $subpath | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
				if ($data.PreCheckDLLPath -ne $null) {
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_policymanagerdlls $subkey.Name $data.PreCheckDLLPath
						if ($result) {
							continue
						}
					}
					if ($data.PreCheckDLLPath -notin $allow_listed_values) {
						Write-SnapshotMessage -Key $subkey.Name -Value $data.PreCheckDLLPath -Source 'PolicyManagerPreCheck'

						$pass = $false
						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_activesetup $item.Name $data.StubPath
							if ($result) {
								$pass = $true
							}
						}
						if ($pass -eq $false) {
							$detection = [PSCustomObject]@{
								Name      = 'Non-Standard Policy Manager DLL'
								Risk      = 'High'
								Source    = 'Registry'
								Technique = "T1546: Event Triggered Execution"
								Meta      = "Path: " + $subkey.Name + ", Entry Name: PreCheckDLLPath, DLL: " + $data.PreCheckDLLPath
							}
							Write-Detection $detection
						}
					}
				}
				if ($data.transportDllPath -ne $null) {
					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_policymanagerdlls $subkey.Name $data.transportDllPath
						if ($result) {
							$pass = $true
						}
					}
					if ($data.transportDllPath -notin $allow_listed_values) {
						Write-SnapshotMessage -Key $subkey.Name -Value $data.transportDllPath -Source 'PolicyManagerTransport'

						if ($pass -eq $false) {
							$detection = [PSCustomObject]@{
								Name      = 'Non-Standard Policy Manager DLL'
								Risk      = 'High'
								Source    = 'Registry'
								Technique = "T1546: Event Triggered Execution"
								Meta      = "Path: " + $subkey.Name + ", Entry Name: transportDllPath, DLL: " + $data.transportDllPath
							}
							Write-Detection $detection
						}
					}
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
	Write-Message "Checking SEMgr Wallet DLLs"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\SEMgr\Wallet"
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
	Write-Message "Checking Error Reporting Handler DLLs"
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
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules"
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

function Test-SilentProcessExitMonitoring {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking SilentProcessExit Monitoring"
	$path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
	if (Test-Path -Path $path) {
		$items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			if ($data.MonitorProcess -ne $null) {
				if ($data.ReportingMode -eq $null) {
					$data.ReportingMode = 'NA'
				}

				Write-SnapshotMessage -Key $item.Name -Value $data.MonitorProcess -Source 'SilentProcessExit'

				if ($loadsnapshot) {
					$detection = [PSCustomObject]@{
						Name      = 'Allowlist Mismatch: Process Launched on SilentProcessExit'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
						Meta      = "Monitored Process: " + $item.Name + ", Launched Process: " + $data.MonitorProcess + ", Reporting Mode: " + $data.ReportingMode
					}
					$result = Assert-IsAllowed $allowtable_silentprocessexit $item.Name $data.MonitorProcess $detection
					if ($result) {
						continue
					}
				}
				#allowtable_silentprocessexit
				$detection = [PSCustomObject]@{
					Name      = 'Process Launched on SilentProcessExit'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546.012: Event Triggered Execution: Image File Execution Options Injection"
					Meta      = "Monitored Process: " + $item.Name + ", Launched Process: " + $data.MonitorProcess + ", Reporting Mode: " + $data.ReportingMode
				}
				Write-Detection $detection
			}
		}
	}
}

function Test-LSA {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking LSA DLLs"
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
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Lsa"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'LSASecurity'

						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_lsasecurity $package $package
							if ($result) {
								continue
							}
						}
						$detection = [PSCustomObject]@{
							Name      = 'LSA Security Package Review'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						Write-Detection $detection
					}
				}
			}
			if ($_.Name -eq 'Authentication Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'LSASecurity'

						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_lsasecurity $package $package
							if ($result) {
								continue
							}
						}
						$detection = [PSCustomObject]@{
							Name      = 'LSA Authentication Package Review'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1547.002: Boot or Logon Autostart Execution: Authentication Packages"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Lsa\OSConfig"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Security Packages' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'LSASecurity'

						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_lsasecurity $package $package
							if ($result) {
								continue
							}
						}
						$detection = [PSCustomObject]@{
							Name      = 'LSA Security Package Review'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\LsaExtensionConfig\LsaSrv"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Extensions' -and $_.Value -ne '""') {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $common_ssp_dlls) {
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'LSASecurity'

						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_lsasecurity $package $package
							if ($result) {
								continue
							}
						}
						$detection = [PSCustomObject]@{
							Name      = 'LSA Extensions Review'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1547.005: Boot or Logon Autostart Execution: Security Support Provider"
							Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						Write-Detection $detection
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
	$path = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Lsa"
	if (Test-Path -Path $path) {
		$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq "Notification Packages") {
				$packages = $_.Value.Split([System.Environment]::NewLine)
				foreach ($package in $packages) {
					if ($package -notin $standard_lsa_notification_packages) {
						Write-SnapshotMessage -Key $_.Name -Value $package -Source 'LSASecurity'

						if ($loadsnapshot) {
							$result = Assert-IsAllowed $allowlist_lsasecurity $package $package
							if ($result) {
								continue
							}
						}
						$detection = [PSCustomObject]@{
							Name      = 'Potential Exploitation via Password Filter DLL'
							Risk      = 'High'
							Source    = 'Registry'
							Technique = "T1556.002: Modify Authentication Process: Password Filter DLL"
							Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value + ", Abnormal Package: " + $package
						}
						Write-Detection $detection
					}
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
	Write-Message "Checking Terminal Services Initial Programs"
	$paths = @(
		"Registry::$regtarget_hklm`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
		"Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Terminal Server\WinStations\RDP-Tcp"
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

function Test-UserInitMPRScripts {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking UserInitMPRLogonScript"
	$basepath = "Registry::HKEY_CURRENT_USER\Environment"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'UserInitMprLogonScript') {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'UserInitMPR'

					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_userinitmpr $_.Name $_.Value
						if ($result -eq $true) {
							return
						}
					}
					$detection = [PSCustomObject]@{
						Name      = 'Potential Persistence via Logon Initialization Script'
						Risk      = 'Medium'
						Source    = 'Registry'
						Technique = "T1037.001: Boot or Logon Initialization Scripts: Logon Script (Windows)"
						Meta      = "Key Location: HKCU\Environment, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
					}
					Write-Detection $detection
				}
			}
		}
	}
}

function Test-WindowsLoadKey {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# TODO - Add Snapshot Skipping
	# Supports Drive Retargeting
	Write-Message "Checking Windows Load"
	$basepath = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path "Registry::$path") {
			$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -in 'Load') {
					Write-SnapshotMessage -Key $_.Name -Value $_.Value -Source 'WindowsLoad'

					$detection = [PSCustomObject]@{
						Name      = 'Potential Windows Load Hijacking'
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