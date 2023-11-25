
function Test-ContextMenu {
	# HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}
	# HKEY_USERS\S-1-5-21-63485881-451500365-4075260605-1001\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}
	# The general idea is that {B7CDF620-DB73-44C0-8611-832B261A0107} represents the Explorer context menu - we are scanning ALL ContextMenuHandlers for DLLs present in the (Default) property as opposed to a CLSID
	# https://ristbs.github.io/2023/02/15/hijack-explorer-context-menu-for-persistence-and-fun.html
	# Supports Drive Retargeting
	# No Snapshotting right now - can add though.
	# TODO - Check ColumnHandlers, CopyHookHandlers, DragDropHandlers and PropertySheetHandlers in same key, HKLM\Software\Classes\*\shellex
	Write-Message "Checking Context Menu Handlers"

	$path = "$regtarget_hklm`SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
	if (Test-Path -LiteralPath "Registry::$path") {
		$items = Get-ChildItem -LiteralPath "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq '(Default)' -and $_.Value -match ".*\.dll.*") {
					Write-SnapshotMessage -Key $item.Name -Value $_.Value -Source 'ContextMenuHandlers'

					$pass = $false
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_contextmenuhandlers $_.Value $_.Value
						if ($result) {
							$pass = $true
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'DLL loaded in ContextMenuHandler'
							Risk      = 'Medium'
							Source    = 'Windows Context Menu'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Key: " + $item.Name + ", DLL: " + $_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}

	$basepath = "HKEY_CURRENT_USER\SOFTWARE\Classes\*\shellex\ContextMenuHandlers"
	foreach ($p in $regtarget_hkcu_list) {
		$path = $basepath.Replace("HKEY_CURRENT_USER", $p)
		if (Test-Path -LiteralPath "Registry::$path") {
			$items = Get-ChildItem -LiteralPath "Registry::$path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
			foreach ($item in $items) {
				$path = "Registry::" + $item.Name
				$data = Get-ItemProperty -LiteralPath $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
				$data.PSObject.Properties | ForEach-Object {
					if ($_.Name -eq '(Default)' -and $_.Value -match ".*\.dll.*") {
						$detection = [PSCustomObject]@{
							Name      = 'DLL loaded in ContextMenuHandler'
							Risk      = 'Medium'
							Source    = 'Windows Context Menu'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Key: " + $item.Name + ", DLL: " + $_.Value
						}
						Write-Detection $detection
					}
				}
			}
		}
	}

}
