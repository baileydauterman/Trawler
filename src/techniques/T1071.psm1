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
	$tcp_connections = Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, OwningProcess, RemoteAddress, RemotePort
	$suspicious_ports = @(20, 21, 22, 23, 25, 137, 139, 445, 3389, 443)
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
	foreach ($conn in $tcp_connections) {
		#allowlist_remote_addresses

		$proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue | Select-Object Name, Path

		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($conn.RemoteAddress, $conn.RemoteAddress, 'Connections'))) {
			continue
		}

		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_remote_addresses $conn.RemoteAddress $conn.RemoteAddress)) {
			continue
		}

		if ($conn.State -eq 'Listen' -and $conn.LocalPort -gt 1024) {
			if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($proc.Name, $proc.Path, 'ProcessConnections'))) {
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
					ProcessPath = $proc.ProcessPath
				}
			)
			$State.WriteDetection($detection)
		}

		if ($conn.State -eq 'Established' -and ($conn.LocalPort -in $suspicious_ports -or $conn.RemotePort -in $suspicious_ports) -and $proc.Name -notin $allow_listed_process_names) {
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
					ProcessPath   = $proc.ProcessPath
				}
			)
			$State.WriteDetection($detection)
		}

		if ($proc.Path) {
			foreach ($path in $suspicious_process_paths) {
				if (($proc.Path).ToLower() -match $path) {
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
							ProcessPath   = $proc.ProcessPath
						}
					)
					$State.WriteDetection($detection)
				}
			}
		}
	}
}