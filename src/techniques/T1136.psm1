function Test-T1136 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-Users $State
}

function Test-Users {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
		$State
	)
	# Supports Dynamic Snapshotting
	# Can possibly support drive retargeting by reading SAM/SYSTEM Hives if intact
	# https://habr.com/en/articles/441410/
	if ($drivechange) {
		$State.WriteMessage("Skipping User Analysis - No Drive Retargeting [yet]")
		return
	}

	$State.WriteMessage("Checking Local Administrators")

	# TODO - Catch error with outdated powershell versions that do not support Get-LocalGroupMember and use alternative gather mechanism
	# Find all local administrators and their last logon time as well as if they are enabled.
	$local_admins = Get-LocalGroupMember -Group "Administrators" | Select-Object *

	foreach ($admin in $local_admins) {
		$admin_user = Get-LocalUser -SID $admin.SID | Select-Object AccountExpires, Description, Enabled, FullName, PasswordExpires, UserMayChangePassword, PasswordLastSet, LastLogon, Name, SID, PrincipalSource

		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($admin.name, $admin.name, "Users"), $true)) {
			continue
		}

		if ($loadsnapshot -and (Assert-IsAllowed $allowlist_users $admin.nam $admin.name)) {
			continue
		}

		$detection = [TrawlerDetection]::new(
			'Local Administrator Account',
			[TrawlerRiskPriority]::Medium,
			'Users',
			"T1136: Create Account",
			[PSCustomObject]@{
				Name      = $admin.Name
				LastLogon = $admin_user.LastLogon
				Enabled   = $admin_user.Enabled
			}
		)

		$State.WriteDetection($detection)
	}
    
}