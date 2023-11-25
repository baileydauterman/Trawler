function Test-DisableLowILProcessIsolation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [TrawlerState]
        $State
    )

	# Supports Drive Retargeting
	# Supports Snapshotting
	Write-Message "Checking for COM Objects running without Low Integrity Isolation"
	$path = "$regtarget_hklm`Software\Classes\CLSID"
	$allowlist = @(
		"@C:\\Program Files\\Microsoft Office\\Root\\VFS\\ProgramFilesCommonX64\\Microsoft Shared\\Office16\\oregres\.dll.*"
		"@wmploc\.dll.*"
		"@C:\\Windows\\system32\\mssvp\.dll.*"
		"@C:\\Program Files\\Common Files\\System\\wab32res\.dll.*"
	)
	if (Test-Path -LiteralPath "Registry::$path") {
		$items = Get-TrawlerChildItem "Registry::$path"
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-TrawlerItemProperty $path
			$data.PSObject.Properties | ForEach-Object {
				if ($_.Name -eq 'DisableLowILProcessIsolation' -and $_.Value -eq 1) {
					Write-SnapshotMessage -Key $item.Name -Value $item.Name -Source 'DisableLowIL'
					if ($data.DisplayName) {
						$displayname = $data.DisplayName
					}
					else {
						$displayname = ""
					}

					$pass = $false
                    
					if ($loadsnapshot) {
						$result = Assert-IsAllowed $allowlist_disablelowil $item.Name $item.Name
						if ($result) {
							$pass = $true
						}
					}
					foreach ($allow in $allowlist) {
						if ($displayname -match $allow) {
							$pass = $true
							break
						}
					}
					if ($pass -eq $false) {
						$detection = [PSCustomObject]@{
							Name      = 'COM Object Registered with flag disabling low-integrity process isolation'
							Risk      = 'Medium'
							Source    = 'Registry'
							Technique = "T1546: Event Triggered Execution"
							Meta      = "Key: " + $item.Name + ", Display Name: " + $displayname
						}
						Write-Detection $detection
					}
				}
			}
		}
	}
}