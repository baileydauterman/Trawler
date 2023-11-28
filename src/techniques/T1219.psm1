function Test-T1219 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-RATS $State
}

function Test-RATS {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	# Supports Dynamic Snapshotting

	# https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects.html
	# https://vikas-singh.notion.site/vikas-singh/Remote-Access-Software-Forensics-3e38d9a66ca0414ca9c882ad67f4f71b#183d1e94c9584aadbb13779bbe77f68e
	# https://support.solarwinds.com/SuccessCenter/s/article/Log-File-Locations-Adjustments-and-Diagnostics-for-DameWare?language=en_US
	# https://digitalforensicsdotblog.wordpress.com/tag/screenconnect/
	# https://docs.getscreen.me/faq/agent/
	# https://helpdesk.kaseya.com/hc/en-gb/articles/229009708-Live-Connect-Log-File-Locations
	# https://support.goto.com/resolve/help/where-do-i-find-goto-resolve-application-logs
	# https://support.radmin.com/index.php/Knowledgebase/Article/View/124/9/Radmin-Installation-Guide

	##### TightVNC
	# -Log Files
	##### UltraVNC
	# -Log Files
	##### RealVNC
	# -Debug Logs - %ProgramData%\RealVBC-Service\vncserver.log
	##### AmmyAdmin
	# -LogFiles
	##### Remote
	##### AnyDesk
	# -Log Files
	##### TeamViewer
	# -Log Files
	# HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer
	##### NinjaOne
	##### Zoho GoTo Assist/GoTo Resolve
	##### Atera
	# https://support.atera.com/hc/en-us/articles/215955967-Troubleshoot-the-Atera-Agent-Windows-
	# HKEY_LOCAL_MACHINE\SOFTWARE\ATERA Networks\AlphaAgent
	# If Reg key exists, Agent was installed at one point
	# Also installs a service named 'AlteraAgent'
	##### ConnectWise/ScreenConnect
	# https://blog.morphisec.com/connectwise-control-abused-again-to-deliver-zeppelin-ransomware
	# Installs service called "ScreenConnect Client"
	# C:\ProgramData\ScreenConnect Client (<string ID>)\user.config
	# C:\Windows\Temp\ScreenConnect\.*\
	##### AnyScreen
	##### RemotePC
	##### BeyondTrust
	##### Remote Desktop Manager
	##### Getscreen
	##### Action1
	##### Webex
	##### Atlassian
	##### Surfly
	##### Electric
	##### Pulseway
	##### Kaseya VSA
	##### XMReality
	##### SightCall
	##### DameWare
	##### ScreenMeet
	##### Viewabo
	##### ShowMyPC
	##### Iperius
	##### Radmin
	##### Remote Utilities
	##### RemoteToPC
	##### LogMeIn
	$State.WriteMessage("Checking Common RAT Artifacts")

	$application_logpaths = @{
		"Action1"                           = ""
		"AmmyAdmin (Log 1)"                 = "$env_programdata\AMMYY\access.log"
		"AmmyAdmin (Dir 1)"                 = "$env_programdata\AMMYY"
		"AnyDesk (Dir 1)"                   = "$env_programdata\AnyDesk"
		"AnyDesk (Dir 2)"                   = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\AnyDesk"
		"AnyDesk (Log 1)"                   = "$env_programdata\AnyDesk\ad.trace"
		"AnyDesk (Log 2)"                   = "$env_programdata\AnyDesk\connection_trace.txt"
		"AnyDesk (Log 3)"                   = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\AnyDesk\ad.trace"
		"AnyDesk (Log 4)"                   = "$env_programdata\AnyDesk\ad_svc.trace"
		"AnyDesk (Log 5)"                   = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\AnyDesk\*.conf"
		"AnyDesk (Reg 1)"                   = "Registry::{0}SYSTEM\*\Services\AnyDesk" -f $($State.DriveTargets.Hklm)
		"AnyDesk (Reg 2)"                   = "Registry::{0}SOFTWARE\Clients\Media\AnyDesk" -f $($State.DriveTargets.Hklm)
		"AnyScreen"                         = ""
		"Bomgar\BeyondTrust (Dir 1)"        = "$($State.DriveTargets.HomeDrive)\Program Files\Bomgar"
		"Bomgar\BeyondTrust (Dir 2)"        = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\Bomgar"
		"Bomgar\BeyondTrust (Dir 3)"        = "$env_programdata\BeyondTrust"
		"Atera\SplashTop (Log 1)"           = "$($State.DriveTargets.HomeDrive)\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageRunCommandInteractive\log.txt"
		"Atera\SplashTop (Log 2)"           = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\*.txt"
		"Atera\SplashTop (Dir 1)"           = "$($State.DriveTargets.HomeDrive)\Program Files\ATERA Networks\AteraAgent"
		"Atera\SplashTop (Reg 1)"           = "Registry::{0}SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 2)"           = "Registry::{0}SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 3)"           = "Registry::{0}SYSTEM\*\Services\EventLog\Application\AlphaAgent" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 4)"           = "Registry::{0}SYSTEM\*\Services\EventLog\Application\AteraAgent" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 5)"           = "Registry::{0}SYSTEM\*\Services\AteraAgent" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 6)"           = "Registry::{0}SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 7)"           = "Registry::{0}SYSTEM\*\Services\SplashtopRemoteService" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 8)"           = "Registry::{0}SYSTEM\*\Control\SafeBoot\Network\SplashtopRemoteService" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 9)"           = "Registry::{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\Splashtop PDF Remote Printer" -f $($State.DriveTargets.Hklm)
		"Atera\SplashTop (Reg 10)"          = "Registry::{0}SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server\ClientInfo" -f $($State.DriveTargets.Hklm)
		"ConnectWise\ScreenConnect (Dir 1)" = "$env_programdata\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 2)" = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 3)" = "$($State.DriveTargets.HomeDrive)\Program Files\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 4)" = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\Temp\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 5)" = "$($State.DriveTargets.HomeDrive)\Windows\temp\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 6)" = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\Documents\ConnectWiseControl"
		"DameWare (Dir 1)"                  = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\temp\dwrrcc downloads"
		"DameWare (Dir 2)"                  = "$($State.DriveTargets.HomeDrive)\Windows\dwrcs"
		"Dameware (Dir 3)"                  = "$env_programdata\DameWare"
		"DameWare (Dir 4)"                  = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\DameWare Development"
		"Dameware (Dir 5)"                  = "$env_programdata\DameWare Development"
		"GetScreen (Dir 1)"                 = "$($State.DriveTargets.HomeDrive)\Program Files\Getscreen.me"
		"GetScreen (Dir 2)"                 = "$env_programdata\Getscreen.me"
		"Iperius (Dir 1)"                   = "$env_programdata\iperius*"
		"Iperius (Dir 2)"                   = "$($State.DriveTargets.HomeDrive)\Program Files\iperius*"
		"Kaseya VSA (Dir 1)"                = "$env_programdata\Kaseya*"
		"Kaseya VSA (Dir 2)"                = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\Kaseya*"
		"Kaseya VSA (Dir 3)"                = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\Kaseya*"
		"LogMeIn (Dir 1)"                   = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\LogMeInIgnition*"
		"NinjaOne"                          = ""
		"Pulseway (Dir 1)"                  = "$($State.DriveTargets.HomeDrive)\Users\*\AppData\Roaming\Pulseway Remote Control"
		"Pulseway (Reg 1)"                  = "Registry::HKCU\Software\MMSOFT Design\Pulseway\Remote Desktop"
		"Pulseway (Reg 2)"                  = "Registry::{0}Software\MMSOFT Design\Pulseway\Remote Desktop" -f $($State.DriveTargets.Hklm)
		"Radmin (Dir 1)"                    = "$($State.DriveTargets.HomeDrive)\Program Files\Radmin*"
		"Radmin (Dir 2)"                    = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\Radmin*"
		"RealVNC (Dir 1)"                   = "$env_programdata\RealVBC-Service"
		"RealVNC (Log 1)"                   = "$env_programdata\RealVBC-Service\vncserver.log"
		"RealVNC (Log 2)"                   = "$env_programdata\RealVBC-Service\vncserver.log.bak"
		"Remote Desktop Manager (Dir 1)"    = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\Devolutions\RemoteDesktopManager"
		"Remote Desktop Manager (Dir 2)"    = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\Devolutions\Remote Desktop Manager"
		"Remote Desktop Manager (Dir 3)"    = "$($State.DriveTargets.HomeDrive)\Program Files\Devolutions\Remote Desktop Manager"
		"RemotePC (Dir 1)"                  = "$env_programdata\RemotePC*"
		"RemotePC (Dir 2)"                  = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\RemotePC*"
		"RemotePC (Dir 3)"                  = "$($State.DriveTargets.HomeDrive)\Program Files\RemotePC*"
		"RemotePC (Dir 4)"                  = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\RemotePC*"
		"RemoteToPC (Dir 1)"                = "$env_programdata\RemoteToPC*"
		"RemoteToPC (Dir 2)"                = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\RemoteToPC*"
		"RemoteToPC (Dir 3)"                = "$($State.DriveTargets.HomeDrive)\Program Files\RemoteToPC*"
		"RemoteToPC (Dir 4)"                = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\RemoteToPC*"
		"Remote Utilities (Dir 1)"          = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\Remote Utilities Agent"
		"Remote Utilities (Dir 2)"          = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\Remote Utilities*"
		"Remote Utilities (Dir 3)"          = "$($State.DriveTargets.HomeDrive)\Program Files\Remote Utilities*"
		"Remote Utilities (Dir 4)"          = "$env_programdata\Remote Utilities*"
		"ScreenMeet (Dir 1)"                = "$env_programdata\Projector Inc\ScreenMeet*"
		"ShowMyPC (Dir 1)"                  = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\Temp\ShowMyPC"
		"ShowMyPC (Dir 2)"                  = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\ShowMyPC"
		"SightCall"                         = ""
		"Surfly"                            = ""
		"Syncro (Dir 1)"                    = "$env_programdata\Syncro"
		"Syncro (Dir 2)"                    = "$($State.DriveTargets.HomeDrive)\Program Files\RepairTech\Syncro"
		"TightVNC (Log 1)"                  = "$($State.DriveTargets.HomeDrive)\Windows\System32\config\systemprofile\AppData\Roaming\TightVNC\tvnserver.log"
		"TightVNC (Log 2)"                  = "$env_programdata\TightVNC\tvnserver.log"
		"TeamViewer (Log 1)"                = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\TeamViewer\Connections.txt"
		"TeamViewer (Log 2)"                = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\Temp\TeamViewer\Connections_incoming.txt"
		"TeamViewer (Log 3)"                = "$($State.DriveTargets.HomeDrive)\Program Files\TeamViewer\Connections_incoming.txt"
		"TeamViewer (Log 4)"                = "$($State.DriveTargets.HomeDrive)\Program Files\TeamViewer\TeamViewer*_Logfile.log"
		"TeamViewer (Log 5)"                = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\TeamViewer\Logs\TeamViewer*_Logfile.log"
		"TeamViewer (Log 6)"                = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\TeamViewer\TeamViewer*_Logfile.log"
		"TeamViewer (Reg 1)"                = "Registry::{0}SOFTWARE\TeamViewer" -f $($State.DriveTargets.Hklm)
		"TeamViewer (Reg 2)"                = "Registry::{0}SYSTEM\*\Services\TeamViewer" -f $($State.DriveTargets.Hklm)
		#"TeamViewer (Reg 3)" = "Registry::{0}SYSTEM\ControlSet001\Services\TeamViewer" -f $($State.DriveTargets.Hklm)
		"UltraVNC (Log 1)"                  = "$env_programdata\uvnc bvba\WinVNC.log"
		"UltraVNC (Log 2)"                  = "$env_programdata\uvnc bvba\mslogon.log"
		"UltraViewer (Dir 1)"               = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\UltraViewer"
		"XMReality"                         = ""
		"Viewabo"                           = ""
		"ZoHo Assist (Dir 1)"               = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\ZohoMeeting"
		"ZoHo Assist (Dir 2)"               = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\GoTo Resolve Applet"
		"ZoHo Assist (Dir 3)"               = "$($State.DriveTargets.HomeDrive)\Program Files (x86)\GoTo Resolve*"
		"ZoHo Assist (Dir 4)"               = "$($State.DriveTargets.HomeDrive)\Users\USER_REPLACE\AppData\Local\GoTo"
	}

	if (Test-Path "$($State.DriveTargets.HomeDrive)\Users") {
		$profile_names = Get-ChildItem "$($State.DriveTargets.HomeDrive)\Users" -Directory | Select-Object *
	}
 else {
		$profile_names = @()
		Write-Warning "[!] Could not find '$($State.DriveTargets.HomeDrive)\Users'!"
	}


	foreach ($item in $application_logpaths.GetEnumerator()) {
		$paths = @()
		$checked_path = $item.Value
		$rat_name = $item.Name
		if ($checked_path -eq "") {
			continue
		}
		if ($profile_names.Count -ne 0) {
			foreach ($user in $profile_names) {
				if ($checked_path -match ".*USER_REPLACE.*") {
					$tmp = $checked_path.Replace("USER_REPLACE", $user.Name)
					$paths += $tmp
				}
				elseif ($checked_path -match ".*HKCU.*") {
					foreach ($p in $State.DriveTargets.HkcuList) {
						$paths += $checked_path.Replace("HKCU", $p)
					}
					break
				}
				else {
					$paths += $checked_path
					break
				}
			}
		}
		else {
			if ($checked_path -match ".*HKCU.*") {
				foreach ($p in $State.DriveTargets.HkcuList) {
					$paths += $checked_path.Replace("HKCU", $p)
				}
			}
			else {
				$paths += $checked_path
			}
		}

		foreach ($tmppath in $paths) {
			if (Test-Path $tmppath) {
				if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($rat_name, $tmppath, 'RATS'), $true)) {
					continue
				}

				$detection = [PSCustomObject]@{
					Name      = 'Remote Access Tool Artifact'
					Risk      = [TrawlerRiskPriority]::Medium
					Source    = 'Software'
					Technique = "T1219: Remote Access Software"
					Meta      = "Possible RAT Artifact: $rat_name, Location: $tmppath"
				}
				$State.WriteDetection($detection)
			}
		}
	}
}