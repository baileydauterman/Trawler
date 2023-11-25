function Test-ComHijacks {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path,
        [Parameter()]
        [PSCustomObject]
        $ComTables,
        [Parameter()]
        [PSCustomObject]
        $TrawlerState
    )

    if (-not (Test-Path -Path $Path)) {
        return $null
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

                Write-SnapshotMessage -Key $data.Name -Value $_.Value -Source 'COM'

                if ($TrawlerState.LoadSnapshot) {
                    $detection = [PSCustomObject]@{
                        Name      = 'Allowlist Mismatch: COM Hijack'
                        Risk      = 'Medium'
                        Source    = 'Registry'
                        Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
                        Meta      = "Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
                    }

                    $result = Assert-IsAllowed $allowtable_com $data.Name $_.Value $detection
                    if ($result) {
                        continue
                    }
                }

                $verified_match = Find-IfValueExistsInComTables -ComTables $ComTables -Key $data.Name -Value $_.Value
                
                if (!($verified_match) -or $_.Value -match "$env:homedrive\\Users\\(public|administrator|guest).*") {
                    $detection = [PSCustomObject]@{
                        Name      = 'Potential COM Hijack'
                        Risk      = 'Medium'
                        Source    = 'Registry'
                        Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
                        Meta      = "Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
                    }
                    Write-Detection $detection
                }
            }
        }
    }
}


function Check-WellKnownCOM {
	# Supports Drive Retargeting
	# TODO - Add the same HKLM Check
	Write-Message "Checking well-known COM hijacks"

	# shell32.dll Hijack
	$basepath = "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				$detection = [PSCustomObject]@{
					Name      = 'Potential shell32.dll Hijack for Persistence'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
					Meta      = "Key Location: HKCU\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1}\\InprocServer32, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
			}
		}
	}
	# WBEM Subsystem
	$basepath = "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID\{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}\InprocServer32"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -Path $path) {
			$items = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$items.PSObject.Properties | ForEach-Object {
				$detection = [PSCustomObject]@{
					Name      = 'Potential WBEM Subsystem Hijack for Persistence'
					Risk      = 'High'
					Source    = 'Registry'
					Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
					Meta      = "Key Location: HKCU\\Software\\Classes\\CLSID\\{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}\\InprocServer32, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				Write-Detection $detection
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
function Check-COM-Hijacks {
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	Write-Message "Checking COM Classes"
	# TODO - Consider NOT alerting when we don't have a 'known-good' entry for the CLSID in question
	# TODO - Some regex appears to be non-functional, especially on HKU inspection - need to figure out why/troubleshoot
	# TODO - Inspect TreatAs options
	# Malware will typically target 'well-known' keys that are present in default versions of Windows - that should be enough for most situations and help to reduce noise.
	$ComTables = Build-ComPaths -HomeDrive $env_assumedhomedrive

	# HKCR
	$path = "HKCR\CLSID_SKIP"
	Test-ComHijacks -Path "Registry::HKCR\CLSID_SKIP" -ComTables $ComTables -TrawlerState $ERROR

	## HKLM
	$default_hklm_com_lookups = @{}
	$default_hklm_com_server_lookups = @{}
	$local_regretarget = $regtarget_hklm + "SOFTWARE\Classes"
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
	$local_regretarget2 = "$regtarget_hklm`SOFTWARE\Classes\CLSID"
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
							Write-SnapshotMessage -Key $data.Name -Value $_.Value -Source 'COM'

							if ($loadsnapshot) {
								$detection = [PSCustomObject]@{
									Name      = 'Allowlist Mismatch: COM Hijack'
									Risk      = 'Medium'
									Source    = 'Registry'
									Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
									Meta      = "Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
								}
								$result = Assert-IsAllowed $allowtable_com $data.Name $_.Value $detection
								if ($result) {
									continue
								}
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
								$detection = [PSCustomObject]@{
									Name      = 'Potential COM Hijack'
									Risk      = 'Medium'
									Source    = 'Registry'
									Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
									Meta      = "Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
								}
								Write-Detection $detection
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
		foreach ($p in $regtarget_hkcu_class_list) {
			$new_name = ($hash.Name).Replace("HKEY_CLASSES_ROOT", "$p\CLSID")
			$default_hkcu_com_lookups["$new_name"] = $hash.Value
		}
	}
	foreach ($hash in $ComTables.Server2022Coms) {
		foreach ($p in $regtarget_hkcu_class_list) {
			$new_name = ($hash.Name).Replace("HKEY_CLASSES_ROOT", "$p\CLSID")
			$default_hkcu_com_server_lookups["$new_name"] = $hash.Value
		}
	}
	foreach ($p in $regtarget_hkcu_class_list) {
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
								Write-SnapshotMessage -Key $data.Name -Value $_.Value -Source 'COM'

								if ($loadsnapshot) {
									$detection = [PSCustomObject]@{
										Name      = 'Allowlist Mismatch: COM Hijack'
										Risk      = 'Medium'
										Source    = 'Registry'
										Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
										Meta      = "Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
									}
									$result = Assert-IsAllowed $allowtable_com $data.Name $_.Value $detection
									if ($result) {
										continue
									}
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

									$detection = [PSCustomObject]@{
										Name      = 'Potential COM Hijack'
										Risk      = 'Medium'
										Source    = 'Registry'
										Technique = "T1546.015: Event Triggered Execution: Component Object Model Hijacking"
										Meta      = "Registry Path: " + $data.Name + ", DLL Path: " + $_.Value
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
}