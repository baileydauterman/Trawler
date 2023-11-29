function Test-T1505 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-TerminalServicesDLL $State
}

function Test-TerminalServicesDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking TerminalServices DLL")
	$path = "Registry::$($State.Drives.Hklm)SYSTEM\CurrentControlSet\Services\TermService\Parameters"
	if (-not (Test-Path -Path $path)) {
		continue 
	}
	
	Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
		if ($_.Name -eq 'ServiceDll' -and $_.Value -ne 'C:\Windows\System32\termsrv.dll') {
			$detection = [TrawlerDetection]::new(
				'Potential Hijacking of Terminal Services DLL',
				[TrawlerRiskPriority]::VeryHigh,
				'Registry',
				"T1505.005: Server Software Component: Terminal Services DLL",
				[PSCustomObject]@{
					KeyLocation = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters"
					EntryName   = $_.Name
					EntryValue  = $_.Value
				}
			)
			$State.WriteDetection($detection)
		}
	}
}
