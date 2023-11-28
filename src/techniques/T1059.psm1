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
		[TrawlerState]
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
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($process.ProcessName, $process.ExecutablePath, "Processes"), $true)) {
			continue
		}

		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_process_exes $process.ProcessName $process.ExecutablePath)) {
			continue
		}

		if (Test-RemoteAccessTrojanTerms -Value $process.CommandLine) {
			$detection = [PSCustomObject]@{
				Name      = 'Running Process has known-RAT Keyword'
				Risk      = [TrawlerRiskPriority]::Medium
				Source    = 'Processes'
				Technique = "T1059: Command and Scripting Interpreter"
				Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath + ", RAT Keyword: " + $term
			}
			$State.WriteDetection($detection)
		}

		if (Test-IPAddress -Value $process.CommandLine) {
			$detection = [PSCustomObject]@{
				Name      = 'IP Address Pattern detected in Process CommandLine'
				Risk      = [TrawlerRiskPriority]::Medium
				Source    = 'Processes'
				Technique = "T1059: Command and Scripting Interpreter"
				Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath
			}
			$State.WriteDetection($detection)
		}
		
		# TODO - Determine if this should be changed to implement allow-listing through a set boolean or stay as-is
		if (Test-SuspiciousProcessPaths -Value $process.ExecutablePath) {
			$detection = [PSCustomObject]@{
				Name      = 'Suspicious Executable Path on Running Process'
				Risk      = [TrawlerRiskPriority]::High
				Source    = 'Processes'
				Technique = "T1059: Command and Scripting Interpreter"
				Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath
			}
			$State.WriteDetection($detection)
		}
	}
}