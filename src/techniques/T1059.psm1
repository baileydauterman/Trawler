function Test-T1059 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-Processes $State
}

function Test-Processes {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Does not support drive retargeting
	# TODO - Check for processes spawned from netsh.dll
	if ($drivechange) {
		$State.WriteMessage("Skipping Process Analysis - No Drive Retargeting")
		return
	}

	$State.WriteMessage("Checking Running Processes")
	$processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName, CreationDate, CommandLine, ExecutablePath, ParentProcessId, ProcessId
	foreach ($process in $processes) {
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($process.ProcessName, $process.ExecutablePath, "Processes"))) {
			continue
		}

		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_process_exes $process.ProcessName $process.ExecutablePath)) {
			continue
		}

		if (Test-RemoteAccessTrojanTerms -Value $process.CommandLine) {
			$detection = [TrawlerDetection]::new(
				'Running Process has known-RAT Keyword',
				[TrawlerRiskPriority]::Medium,
				'Processes',
				"T1059: Command and Scripting Interpreter",
				[PSCustomObject]@{
					ProcessName    = $process.ProcessName
					CommandLine    = $process.CommandLine
					ExecutablePath = $process.ExecutablePath
					RATKeyword     = $term
				}
			)
			$State.WriteDetection($detection)
		}

		if (Test-IPAddress -Value $process.CommandLine) {
			$detection = [TrawlerDetection]::new(
				'IP Address Pattern detected in Process CommandLine',
				[TrawlerRiskPriority]::Medium,
				'Processes',
				"T1059: Command and Scripting Interpreter",
				($process | Select-Object ProcessName, CommandLine, Executable)
			)
			$State.WriteDetection($detection)
		}
		
		# TODO - Determine if this should be changed to implement allow-listing through a set boolean or stay as-is
		if (Test-SuspiciousProcessPaths -Value $process.ExecutablePath) {
			$detection = [TrawlerDetection]::new(
				'Suspicious Executable Path on Running Process',
				[TrawlerRiskPriority]::High,
				'Processes',
				"T1059: Command and Scripting Interpreter",
				($process | Select-Object ProcessName, CommandLine, Executable)
			)
			$State.WriteDetection($detection)
		}
	}
}