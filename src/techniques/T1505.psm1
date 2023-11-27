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
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking TerminalServices DLL")
	$path = "Registry::$($State.DriveTargets.Hklm)SYSTEM\CurrentControlSet\Services\TermService\Parameters"
	if (-not (Test-Path -Path $path)) {
		continue 
	}
	
	Get-TrawlerItemData -Path $path -ItemType ItemProperty | ForEach-Object {
		if ($_.Name -eq 'ServiceDll' -and $_.Value -ne 'C:\Windows\System32\termsrv.dll') {
			$detection = [PSCustomObject]@{
				Name      = 'Potential Hijacking of Terminal Services DLL'
				Risk      = [TrawlerRiskPriority]::VeryHigh
				Source    = 'Registry'
				Technique = "T1505.005: Server Software Component: Terminal Services DLL"
				Meta      = "Key Location: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
			}
			$State.WriteDetection($detection)
		}
	}
}
