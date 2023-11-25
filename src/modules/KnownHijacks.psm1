function Check-UtilmanHijack {
    # TODO - Add Better Details
    # Supports Drive Retargeting
    Write-Message "Checking utilman.exe"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
    if (Test-Path -Path $path) {
        $detection = [PSCustomObject]@{
            Name      = 'Potential utilman.exe Registry Persistence'
            Risk      = 'High'
            Source    = 'Registry'
            Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
            Meta      = "Review Data for Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
        }
        Write-Detection $detection
    }
}

function Check-SethcHijack {
    # TODO - Add Better Details
    # Supports Drive Retargeting
    Write-Message "Checking sethc.exe"
    $path = "Registry::$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
    if (Test-Path -Path $path) {
        $detection = [PSCustomObject]@{
            Name      = 'Potential sethc.exe Registry Persistence'
            Risk      = 'High'
            Source    = 'Registry'
            Technique = "T1546.008: Event Triggered Execution: Accessibility Features"
            Meta      = "Review Data for Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
        }
        Write-Detection $detection
    }
}
function Check-Service-Hijacks {
    Write-Message "Checking Un-Quoted Services"
    # Supports Drive Retargeting, assumes homedrive is C:
    #$services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
    $service_path = "$regtarget_hklm`SYSTEM\$currentcontrolset\Services"
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

function Check-PATH-Hijacks {
    # Supports Dynamic Snapshotting
    # Mostly supports drive retargeting - assumed PATH is prefixed with C:
    # Data Stored at HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Environment
    # Can just collect from this key instead of actual PATH var
    Write-Message "Checking PATH Hijacks"
    $system32_path = "$env_homedrive\windows\system32"
    $system32_bins = Get-ChildItem -File -Path $system32_path  -ErrorAction SilentlyContinue | Where-Object { $_.extension -in ".exe" } | Select-Object Name
    $sys32_bins = New-Object -TypeName "System.Collections.ArrayList"

    foreach ($bin in $system32_bins) {
        $sys32_bins.Add($bin.Name) | Out-Null
    }
    $path_reg = "Registry::$regtarget_hklm`SYSTEM\$currentcontrolset\Control\Session Manager\Environment"
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

function Check-Association-Hijack {
    # Supports Dynamic Snapshotting
    # Supports Drive Retargeting
    Write-Message "Checking File Associations"
    $homedrive = $env_assumedhomedrive
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
    foreach ($p in $regtarget_hkcu_class_list) {
        $path = $basepath.Replace("HKEY_CURRENT_USER", $p)
        if (Test-Path -Path $path) {
            $items = Get-ChildItem -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
            foreach ($item in $items) {
                $path = $item.Name
                if ($path.EndsWith('file')) {
                    $basefile = $path.Split("\")[-1]
                    $open_path = $path + "\shell\open\command"
                    if (Test-Path -Path "Registry::$open_path") {
                        $key = Get-ItemProperty -Path "Registry::$open_path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
                        $key.PSObject.Properties | ForEach-Object {
                            if ($_.Name -eq '(default)') {
                                #Write-Host $open_path $_.Value
                                $exe = $_.Value
                                $detection_triggered = $false
                                Write-SnapshotMessage -Key $open_path -Value $exe -Source 'AssociationHijack'
                                if ($loadsnapshot) {
                                    $detection = [PSCustomObject]@{
                                        Name      = 'Allowlist Mismatch: Possible File Association Hijack - Mismatch on Expected Value'
                                        Risk      = 'Medium'
                                        Source    = 'Registry'
                                        Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                        Meta      = "FileType: " + $open_path + ", Expected Association: " + $allowtable_fileassocations[$open_path] + ", Current Association: " + $exe
                                    }
                                    $result = Assert-IsAllowed $allowtable_fileassocations $open_path $exe $detection
                                    if ($result) {
                                        continue
                                    }
                                }

                                if ($value_regex_lookup.ContainsKey($basefile)) {
                                    if ($exe -notmatch $value_regex_lookup[$basefile]) {
                                        $detection = [PSCustomObject]@{
                                            Name      = 'Possible File Association Hijack - Mismatch on Expected Value'
                                            Risk      = 'High'
                                            Source    = 'Registry'
                                            Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                            Meta      = "FileType: " + $open_path + ", Expected Association: " + $value_regex_lookup[$basefile] + ", Current Association: " + $exe
                                        }
                                        Write-Detection $detection
                                        return
                                    }
                                    else {
                                        return
                                    }
                                }

                                if ($exe -match ".*\.exe.*\.exe") {
                                    $detection = [PSCustomObject]@{
                                        Name      = 'Possible File Association Hijack - Multiple EXEs'
                                        Risk      = 'High'
                                        Source    = 'Registry'
                                        Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                        Meta      = "FileType: " + $open_path + ", Current Association: " + $exe
                                    }
                                    Write-Detection $detection
                                    return
                                }
                                if ($exe -match $suspicious_terms) {
                                    $detection = [PSCustomObject]@{
                                        Name      = 'Possible File Association Hijack - Suspicious Keywords'
                                        Risk      = 'High'
                                        Source    = 'Registry'
                                        Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                        Meta      = "FileType: " + $open_path + ", Current Association: " + $exe
                                    }
                                    Write-Detection $detection
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    $basepath = "Registry::$regtarget_hklm`SOFTWARE\Classes"
    if (Test-Path -Path $basepath) {
        $items = Get-ChildItem -Path $basepath | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
        foreach ($item in $items) {
            $path = $item.Name
            if ($path.EndsWith('file')) {
                $basefile = $path.Split("\")[-1]
                $open_path = $path + "\shell\open\command"
                if (Test-Path -Path "Registry::$open_path") {
                    $key = Get-ItemProperty -Path "Registry::$open_path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
                    $key.PSObject.Properties | ForEach-Object {
                        if ($_.Name -eq '(default)') {
                            #Write-Host $open_path $_.Value
                            $exe = $_.Value
                            $detection_triggered = $false
                            Write-SnapshotMessage -Key $open_path -Value $exe -Source 'AssociationHijack'

                            if ($loadsnapshot) {
                                $detection = [PSCustomObject]@{
                                    Name      = 'Allowlist Mismatch: Possible File Association Hijack - Mismatch on Expected Value'
                                    Risk      = 'Medium'
                                    Source    = 'Registry'
                                    Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                    Meta      = "FileType: " + $open_path + ", Expected Association: " + $allowtable_fileassocations[$open_path] + ", Current Association: " + $exe
                                }
                                $result = Assert-IsAllowed $allowtable_fileassocations $open_path $exe $detection
                                if ($result) {
                                    continue
                                }
                            }

                            if ($value_regex_lookup.ContainsKey($basefile)) {
                                if ($exe -notmatch $value_regex_lookup[$basefile]) {
                                    $detection = [PSCustomObject]@{
                                        Name      = 'Possible File Association Hijack - Mismatch on Expected Value'
                                        Risk      = 'High'
                                        Source    = 'Registry'
                                        Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                        Meta      = "FileType: " + $open_path + ", Expected Association: " + $value_regex_lookup[$basefile] + ", Current Association: " + $exe
                                    }
                                    Write-Detection $detection
                                    return
                                }
                                else {
                                    return
                                }
                            }

                            if ($exe -match ".*\.exe.*\.exe") {
                                $detection = [PSCustomObject]@{
                                    Name      = 'Possible File Association Hijack - Multiple EXEs'
                                    Risk      = 'High'
                                    Source    = 'Registry'
                                    Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                    Meta      = "FileType: " + $open_path + ", Current Association: " + $exe
                                }
                                Write-Detection $detection
                                return
                            }
                            if ($exe -match $suspicious_terms) {
                                $detection = [PSCustomObject]@{
                                    Name      = 'Possible File Association Hijack - Suspicious Keywords'
                                    Risk      = 'High'
                                    Source    = 'Registry'
                                    Technique = "T1546.001: Event Triggered Execution: Change Default File Association"
                                    Meta      = "FileType: " + $open_path + ", Current Association: " + $exe
                                }
                                Write-Detection $detection
                            }
                        }
                    }
                }
            }
        }
    }
}

function Check-Debugger-Hijacks {
	Write-Message "Checking Debuggers"
	# Partially Supports Dynamic Snapshotting
	# Support Drive Retargeting
	function Check-Debugger-Hijack-Allowlist ($key, $val) {
		if ($loadsnapshot) {
			$detection = [PSCustomObject]@{
				Name      = 'Allowlist Mismatch: Debugger'
				Risk      = 'Medium'
				Source    = 'Registry'
				Technique = "T1546: Event Triggered Execution"
				Meta      = "Key Location: $key, Entry Value: " + $val
			}
			$result = Assert-IsAllowed $allowtable_debuggers $key $val $detection
			if ($result) {
				return $true
			}
		}
		return $false
	}
	# TODO - Rearrange this code to use an array of paths and key names
	# allowtable_debuggers
	# Debugger Hijacks
	# AeDebug 32
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -in 'Debugger') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential AeDebug Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebugProtected"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ProtectedDebugger') {
				Write-SnapshotMessage -Key $path -Value $_.Value-Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if ($_.Name -eq 'ProtectedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential AeDebug Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}

	# AeDebug 64
	$path = "$regtarget_hklm`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Debugger') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if ($_.Name -eq 'Debugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential AeDebug Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	$path = "$regtarget_hklm`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebugProtected"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'ProtectedDebugger') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if ($_.Name -eq 'ProtectedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" -p %ld -e %ld -j 0x%p" -and $pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential AeDebug Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}

	# .NET 32
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\.NETFramework"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'DbgManagedDebugger') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if ($_.Name -eq 'DbgManagedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" PID %d APPDOM %d EXTEXT `"%s`" EVTHDL %d" -and $pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential .NET Debugger Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	# .NET 64
	$path = "$regtarget_hklm`SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'DbgManagedDebugger') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if ($_.Name -eq 'DbgManagedDebugger' -and $_.Value -ne "`"$env:homedrive\Windows\system32\vsjitdebugger.exe`" PID %d APPDOM %d EXTEXT `"%s`" EVTHDL %d" -and $pass -eq $false) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential .NET Debugger Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	# Microsoft Script Debugger
	$path = "$regtarget_hklm`SOFTWARE\Classes\CLSID\{834128A2-51F4-11D0-8F20-00805F2CD064}\LocalServer32"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq '@') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if ($_.Name -eq '@' -and $pass -eq $false -and ($_.Value -ne "`"$env:homedrive\Program Files(x86)\Microsoft Script Debugger\msscrdbg.exe`"" -or $_.Value -ne "`"$env:homedrive\Program Files\Microsoft Script Debugger\msscrdbg.exe`"")) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Microsoft Script Debugger Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	$basepath = "HKEY_CLASSES_ROOT\CLSID\{834128A2-51F4-11D0-8F20-00805F2CD064}\LocalServer32"
	foreach ($p in $regtarget_hkcu_class_list) {
		$path = $basepath.Replace("HKEY_CLASSES_ROOT", $p)
		if (Test-Path -Path "Registry::$path") {
			$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$item.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '@') {
					Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

					if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
						$pass = $true
					}
				}
				if ($_.Name -eq '@' -and $pass -eq $false -and ($_.Value -ne "`"$env_assumedhomedrive\Program Files(x86)\Microsoft Script Debugger\msscrdbg.exe`"" -or $_.Value -ne "`"$env_assumedhomedrive\Program Files\Microsoft Script Debugger\msscrdbg.exe`"")) {
					$detection = [PSCustomObject]@{
						Name      = 'Potential Microsoft Script Debugger Hijacking'
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
	# Process Debugger
	$path = "$regtarget_hklm`SOFTWARE\Classes\CLSID\{78A51822-51F4-11D0-8F20-00805F2CD064}\InprocServer32"
	$pass = $false
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq '(default)') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					$pass = $true
				}
			}
			if (($_.Name -in '(default)' -and $pass -eq $false -and $_.Value -ne "$env_assumedhomedrive\Program Files\Common Files\Microsoft Shared\VS7Debug\pdm.dll") -or ($_.Name -eq '@' -and $_.Value -ne "`"$env_assumedhomedrive\WINDOWS\system32\pdm.dll`"")) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Process Debugger Hijacking'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546: Event Triggered Execution"
					Meta      = "Key Location: $path, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	# WER Debuggers
	$path = "$regtarget_hklm`SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs"
	if (Test-Path -Path "Registry::$path") {
		$item = Get-ItemProperty -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		$item.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Debugger') {
				Write-SnapshotMessage -Key $path -Value $_.Value -Source 'Debuggers'

				if (Check-Debugger-Hijack-Allowlist $path $_.Value) {
					continue
				}
			}
			if ($_.Name -in 'Debugger', 'ReflectDebugger') {
				$detection = [PSCustomObject]@{
					Name      = 'Potential WER Debugger Hijacking'
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