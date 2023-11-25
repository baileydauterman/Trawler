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
		Write-Message "Skipping Process Analysis - No Drive Retargeting"
		return
	}

	Write-Message "Checking Running Processes"
	$processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessName, CreationDate, CommandLine, ExecutablePath, ParentProcessId, ProcessId
	foreach ($process in $processes) {
		Write-SnapshotMessage -Key $process.ProcessName -Value $process.ExecutablePath -Source "Processes"

		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_process_exes $process.ProcessName $process.ExecutablePath)) {
			continue
		}

		ForEach ($term in $rat_terms) {
			if ($process.CommandLine -match ".*$term.*") {
				$detection = [PSCustomObject]@{
					Name      = 'Running Process has known-RAT Keyword'
					Risk      = 'Medium'
					Source    = 'Processes'
					Technique = "T1059: Command and Scripting Interpreter"
					Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath + ", RAT Keyword: " + $term
				}
				Write-Detection $detection
			}
		}
		if ($process.CommandLine -match $ipv4_pattern -or $process.CommandLine -match $ipv6_pattern) {
			$detection = [PSCustomObject]@{
				Name      = 'IP Address Pattern detected in Process CommandLine'
				Risk      = 'Medium'
				Source    = 'Processes'
				Technique = "T1059: Command and Scripting Interpreter"
				Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath
			}
			Write-Detection $detection
		}
		# TODO - Determine if this should be changed to implement allow-listing through a set boolean or stay as-is
		foreach ($path in $suspicious_process_paths) {
			if ($process.ExecutablePath -match $path) {
				$detection = [PSCustomObject]@{
					Name      = 'Suspicious Executable Path on Running Process'
					Risk      = 'High'
					Source    = 'Processes'
					Technique = "T1059: Command and Scripting Interpreter"
					Meta      = "Process Name: " + $process.ProcessName + ", CommandLine: " + $process.CommandLine + ", Executable: " + $process.ExecutablePath
				}
				Write-Detection $detection
			}
		}

	}
}