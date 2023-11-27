function Test-T1484 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-GPOExtensions $State
}

function Test-GPOExtensions {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Supports Drive Retargeting
	$State.WriteMessage("Checking GPO Extension DLLs")
	
	$gpo_dll_allowlist = @(
		"$($State.DriveTargets.HomeDrive)\Windows\System32\TsUsbRedirectionGroupPolicyExtension.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\cscobj.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\dskquota.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\gpprefcl.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\gpscript.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\iedkcs32.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\polstore.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\srchadmin.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\System32\tsworkspace.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\system32\domgmt.dll"
		"$($State.DriveTargets.HomeDrive)\Windows\system32\gpprnext.dll"
		"AppManagementConfiguration.dll"
		"WorkFoldersGPExt.dll"
		"appmgmts.dll"
		"auditcse.dll"
		"dggpext.dll"
		"domgmt.dll"
		"dmenrollengine.dll"
		"dot3gpclnt.dll"
		"fdeploy.dll"
		"gptext.dll"
		"gpprefcl.dll"
		"gpscript.dll"
		"hvsigpext.dll"
		"pwlauncher.dll"
		"scecli.dll"
		"wlgpclnt.dll"
	)

	$path = "$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions"
	if (Test-Path -Path "Registry::$path") {
		$items = Get-ChildItem -Path "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
				if ($_.Name -eq 'DllName' -and $_.Value -notin $gpo_dll_allowlist) {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.Name, $_.Value, 'GPOExtensions'), $true)) {
						continue
					}

					$detection = [PSCustomObject]@{
						Name      = 'Review: Non-Standard GPO Extension DLL'
						Risk      = [TrawlerRiskPriority]::Medium
						Source    = 'Windows GPO Extensions'
						Technique = "T1484.001: Domain Policy Modification: Group Policy Modification"
						Meta      = "Key: " + $item.Name + ", DLL: " + $_.Value
					}

					$State.WriteDetection($detection)
				}
			}
		}
	}
}