function Test-Narrator {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	
	# Supports Drive Retargeting
	# https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
	Write-Message "Checking Narrator MSTTSLocEnUS.dll Presence"
	$basepath = "$env_homedrive\Windows\System32\Speech\Engines\TTS\MSTTSLocEnUS.DLL"
	if (Test-Path $basepath) {
		$item = Get-Item -Path $basepath -ErrorAction SilentlyContinue | Select-Object *
		$detection = [PSCustomObject]@{
			Name      = 'Narrator Missing DLL is Present'
			Risk      = 'Medium'
			Source    = 'Windows Narrator'
			Technique = "T1546: Event Triggered Execution"
			Meta      = "File: " + $item.FullName + ", Created: " + $item.CreationTime + ", Last Modified: " + $item.LastWriteTime
		}
		Write-Detection $detection
	}
}