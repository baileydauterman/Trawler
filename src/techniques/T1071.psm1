function Test-T1071 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-Connections $State
}

function Test-Connections {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Does not support drive-retargeting
	if ($drivechange) {
		$State.WriteMessage("Skipping Network Connections - No Drive Retargeting")
		return
	}

	$State.WriteMessage("Checking Network Connections")
	$allow_listed_process_names = @(
		"brave",
		"chrome",
		"Discord",
		"firefox",
		"GitHubDesktop",
		"iexplorer",
		"msedge",
		"officeclicktorun"
		"OneDrive",
		"safari",
		"SearchApp",
		"Spotify",
		"steam"		
	)

	foreach ($conn in Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, OwningProcess, RemoteAddress, RemotePort) {
		#allowlist_remote_addresses

		$proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue | Select-Object Name, Path

		if ($State.IsExemptBySnapShot($conn.RemoteAddress, $conn.RemoteAddress, 'Connections')) {
			continue
		}

		if ($conn.State -eq 'Listen' -and $conn.LocalPort -gt 1024) {
			if ($State.IsExemptBySnapShot($proc.Name, $proc.Path, 'ProcessConnections')) {
				continue
			}

			$detection = [TrawlerDetection]::new(
				'Process Listening on Ephemeral Port',
				[TrawlerRiskPriority]::VeryLow,
				'Network Connections',
				"T1071: Application Layer Protocol",
				[PSCustomObject]@{
					LocalPort   = $conn.LocalPort
					PID         = $conn.OwningProcess
					ProcessName = $proc.Name
					ProcessPath = $proc.Path
				}
			)

			$State.WriteDetection($detection)
		}

		if ($conn.State -eq 'Established' -and (Test-TrawlerSuspiciousPorts -Values $conn.LocalPort, $conn.RemotePort) -and $proc.Name -notin $allow_listed_process_names) {
			$detection = [TrawlerDetection]::new(
				'Established Connection on Suspicious Port',
				[TrawlerRiskPriority]::Low,
				'Network Connections',
				"T1071: Application Layer Protocol",
				[PSCustomObject]@{
					LocalPort     = $conn.LocalPort
					RemotePort    = $conn.RemotePort
					RemoteAddress = $conn.RemoteAddress
					PID           = $conn.OwningProcess
					ProcessName   = $proc.Name
					ProcessPath   = $proc.Path
				}
			)
			$State.WriteDetection($detection)
		}

		if ($proc.Path -and (Test-SuspiciousProcessPaths -Value $proc.Path)) {
			$detection = [TrawlerDetection]::new(
				'Process running from suspicious path has Network Connection',
				[TrawlerRiskPriority]::High,
				'Network Connections',
				"T1071: Application Layer Protocol",
				[PSCustomObject]@{
					LocalPort     = $conn.LocalPort
					RemotePort    = $conn.RemotePort
					RemoteAddress = $conn.RemoteAddress
					PID           = $conn.OwningProcess
					ProcessName   = $proc.Name
					ProcessPath   = $proc.Path
				}
			)

			$State.WriteDetection($detection)
		}
	}
}