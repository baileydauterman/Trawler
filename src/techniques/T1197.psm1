function Test-T19997 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-BITS $State
}

function Test-BITS {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Maybe with Drive Retargeting
	# C:\ProgramData\Microsoft\Network\Downloader
	# https://www.giac.org/paper/gcih/28198/bits-forensics/130713#:~:text=These%20files%20are%20named%20%E2%80%9Cqmgr0,Microsoft%5CNetwork%5CDownloader%E2%80%9D.
	if ($drivechange) {
		$State.WriteMessage("Skipping BITS Analysis - No Drive Retargeting [yet]")
		return
	}
	$State.WriteMessage("Checking BITS Jobs")
	$bits = Get-BitsTransfer -AllUsers | Select-Object *
	foreach ($item in $bits) {
		if ($item.NotifyCmdLine) {
			$cmd = [string]$item.NotifyCmdLine
		}
		else {
			$cmd = ''
		}
        
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($item.DisplayName, $cmd, 'BITS'), $true)) {
			continue
		}

		$detection = [TrawlerDetection]::new(
			'BITS Item Review',
			[TrawlerRiskPriority]::Low,
			'BITS',
			"T1197: BITS Jobs",
			[PSCustomObject]@{
				ItemName     = $item.DisplayName
				TransferType = $item.TransferType
				JobState     = $item.JobState
				User         = $item.OwnerAccount
				Command      = $cmd
			}
		)
		$State.WriteDetection($detection)
	}
}