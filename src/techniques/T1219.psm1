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
		[object]
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
		"AmmyAdmin (Log 1)"                 = "$($State.Drives.ProgramData)\AMMYY\access.log"
		"AmmyAdmin (Dir 1)"                 = "$($State.Drives.ProgramData)\AMMYY"
		"AnyDesk (Dir 1)"                   = "$($State.Drives.ProgramData)\AnyDesk"
		"AnyDesk (Dir 2)"                   = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\AnyDesk"
		"AnyDesk (Log 1)"                   = "$($State.Drives.ProgramData)\AnyDesk\ad.trace"
		"AnyDesk (Log 2)"                   = "$($State.Drives.ProgramData)\AnyDesk\connection_trace.txt"
		"AnyDesk (Log 3)"                   = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\AnyDesk\ad.trace"
		"AnyDesk (Log 4)"                   = "$($State.Drives.ProgramData)\AnyDesk\ad_svc.trace"
		"AnyDesk (Log 5)"                   = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\AnyDesk\*.conf"
		"AnyDesk (Reg 1)"                   = "Registry::{0}SYSTEM\*\Services\AnyDesk" -f $($State.Drives.Hklm)
		"AnyDesk (Reg 2)"                   = "Registry::{0}SOFTWARE\Clients\Media\AnyDesk" -f $($State.Drives.Hklm)
		"AnyScreen"                         = ""
		"Bomgar\BeyondTrust (Dir 1)"        = "$($State.Drives.HomeDrive)\Program Files\Bomgar"
		"Bomgar\BeyondTrust (Dir 2)"        = "$($State.Drives.HomeDrive)\Program Files (x86)\Bomgar"
		"Bomgar\BeyondTrust (Dir 3)"        = "$($State.Drives.ProgramData)\BeyondTrust"
		"Atera\SplashTop (Log 1)"           = "$($State.Drives.HomeDrive)\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageRunCommandInteractive\log.txt"
		"Atera\SplashTop (Log 2)"           = "$($State.Drives.HomeDrive)\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\*.txt"
		"Atera\SplashTop (Dir 1)"           = "$($State.Drives.HomeDrive)\Program Files\ATERA Networks\AteraAgent"
		"Atera\SplashTop (Reg 1)"           = "Registry::{0}SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 2)"           = "Registry::{0}SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 3)"           = "Registry::{0}SYSTEM\*\Services\EventLog\Application\AlphaAgent" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 4)"           = "Registry::{0}SYSTEM\*\Services\EventLog\Application\AteraAgent" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 5)"           = "Registry::{0}SYSTEM\*\Services\AteraAgent" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 6)"           = "Registry::{0}SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 7)"           = "Registry::{0}SYSTEM\*\Services\SplashtopRemoteService" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 8)"           = "Registry::{0}SYSTEM\*\Control\SafeBoot\Network\SplashtopRemoteService" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 9)"           = "Registry::{0}SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\Splashtop PDF Remote Printer" -f $($State.Drives.Hklm)
		"Atera\SplashTop (Reg 10)"          = "Registry::{0}SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server\ClientInfo" -f $($State.Drives.Hklm)
		"ConnectWise\ScreenConnect (Dir 1)" = "$($State.Drives.ProgramData)\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 2)" = "$($State.Drives.HomeDrive)\Program Files (x86)\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 3)" = "$($State.Drives.HomeDrive)\Program Files\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 4)" = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\Temp\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 5)" = "$($State.Drives.HomeDrive)\Windows\temp\ScreenConnect*"
		"ConnectWise\ScreenConnect (Dir 6)" = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\Documents\ConnectWiseControl"
		"DameWare (Dir 1)"                  = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\temp\dwrrcc downloads"
		"DameWare (Dir 2)"                  = "$($State.Drives.HomeDrive)\Windows\dwrcs"
		"Dameware (Dir 3)"                  = "$($State.Drives.ProgramData)\DameWare"
		"DameWare (Dir 4)"                  = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\DameWare Development"
		"Dameware (Dir 5)"                  = "$($State.Drives.ProgramData)\DameWare Development"
		"GetScreen (Dir 1)"                 = "$($State.Drives.HomeDrive)\Program Files\Getscreen.me"
		"GetScreen (Dir 2)"                 = "$($State.Drives.ProgramData)\Getscreen.me"
		"Iperius (Dir 1)"                   = "$($State.Drives.ProgramData)\iperius*"
		"Iperius (Dir 2)"                   = "$($State.Drives.HomeDrive)\Program Files\iperius*"
		"Kaseya VSA (Dir 1)"                = "$($State.Drives.ProgramData)\Kaseya*"
		"Kaseya VSA (Dir 2)"                = "$($State.Drives.HomeDrive)\Program Files (x86)\Kaseya*"
		"Kaseya VSA (Dir 3)"                = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\Kaseya*"
		"LogMeIn (Dir 1)"                   = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\LogMeInIgnition*"
		"NinjaOne"                          = ""
		"Pulseway (Dir 1)"                  = "$($State.Drives.HomeDrive)\Users\*\AppData\Roaming\Pulseway Remote Control"
		"Pulseway (Reg 1)"                  = "Registry::HKCU\Software\MMSOFT Design\Pulseway\Remote Desktop"
		"Pulseway (Reg 2)"                  = "Registry::$($State.Drives.Hklm)Software\MMSOFT Design\Pulseway\Remote Desktop"
		"Radmin (Dir 1)"                    = "$($State.Drives.HomeDrive)\Program Files\Radmin*"
		"Radmin (Dir 2)"                    = "$($State.Drives.HomeDrive)\Program Files (x86)\Radmin*"
		"RealVNC (Dir 1)"                   = "$($State.Drives.ProgramData)\RealVBC-Service"
		"RealVNC (Log 1)"                   = "$($State.Drives.ProgramData)\RealVBC-Service\vncserver.log"
		"RealVNC (Log 2)"                   = "$($State.Drives.ProgramData)\RealVBC-Service\vncserver.log.bak"
		"Remote Desktop Manager (Dir 1)"    = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\Devolutions\RemoteDesktopManager"
		"Remote Desktop Manager (Dir 2)"    = "$($State.Drives.HomeDrive)\Program Files (x86)\Devolutions\Remote Desktop Manager"
		"Remote Desktop Manager (Dir 3)"    = "$($State.Drives.HomeDrive)\Program Files\Devolutions\Remote Desktop Manager"
		"RemotePC (Dir 1)"                  = "$($State.Drives.ProgramData)\RemotePC*"
		"RemotePC (Dir 2)"                  = "$($State.Drives.HomeDrive)\Program Files (x86)\RemotePC*"
		"RemotePC (Dir 3)"                  = "$($State.Drives.HomeDrive)\Program Files\RemotePC*"
		"RemotePC (Dir 4)"                  = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\RemotePC*"
		"RemoteToPC (Dir 1)"                = "$($State.Drives.ProgramData)\RemoteToPC*"
		"RemoteToPC (Dir 2)"                = "$($State.Drives.HomeDrive)\Program Files (x86)\RemoteToPC*"
		"RemoteToPC (Dir 3)"                = "$($State.Drives.HomeDrive)\Program Files\RemoteToPC*"
		"RemoteToPC (Dir 4)"                = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\RemoteToPC*"
		"Remote Utilities (Dir 1)"          = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\Remote Utilities Agent"
		"Remote Utilities (Dir 2)"          = "$($State.Drives.HomeDrive)\Program Files (x86)\Remote Utilities*"
		"Remote Utilities (Dir 3)"          = "$($State.Drives.HomeDrive)\Program Files\Remote Utilities*"
		"Remote Utilities (Dir 4)"          = "$($State.Drives.ProgramData)\Remote Utilities*"
		"ScreenMeet (Dir 1)"                = "$($State.Drives.ProgramData)\Projector Inc\ScreenMeet*"
		"ShowMyPC (Dir 1)"                  = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\Temp\ShowMyPC"
		"ShowMyPC (Dir 2)"                  = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\ShowMyPC"
		"SightCall"                         = ""
		"Surfly"                            = ""
		"Syncro (Dir 1)"                    = "$($State.Drives.ProgramData)\Syncro"
		"Syncro (Dir 2)"                    = "$($State.Drives.HomeDrive)\Program Files\RepairTech\Syncro"
		"TightVNC (Log 1)"                  = "$($State.Drives.HomeDrive)\Windows\System32\config\systemprofile\AppData\Roaming\TightVNC\tvnserver.log"
		"TightVNC (Log 2)"                  = "$($State.Drives.ProgramData)\TightVNC\tvnserver.log"
		"TeamViewer (Log 1)"                = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\TeamViewer\Connections.txt"
		"TeamViewer (Log 2)"                = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\Temp\TeamViewer\Connections_incoming.txt"
		"TeamViewer (Log 3)"                = "$($State.Drives.HomeDrive)\Program Files\TeamViewer\Connections_incoming.txt"
		"TeamViewer (Log 4)"                = "$($State.Drives.HomeDrive)\Program Files\TeamViewer\TeamViewer*_Logfile.log"
		"TeamViewer (Log 5)"                = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\TeamViewer\Logs\TeamViewer*_Logfile.log"
		"TeamViewer (Log 6)"                = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\TeamViewer\TeamViewer*_Logfile.log"
		"TeamViewer (Reg 1)"                = "Registry::$($State.Drives.Hklm)SOFTWARE\TeamViewer"
		"TeamViewer (Reg 2)"                = "Registry::$($State.Drives.Hklm)SYSTEM\*\Services\TeamViewer"
		# "TeamViewer (Reg 3)" = "Registry::{0}SYSTEM\ControlSet001\Services\TeamViewer" -f $($State.Drives.Hklm)
		"UltraVNC (Log 1)"                  = "$($State.Drives.ProgramData)\uvnc bvba\WinVNC.log"
		"UltraVNC (Log 2)"                  = "$($State.Drives.ProgramData)\uvnc bvba\mslogon.log"
		"UltraViewer (Dir 1)"               = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Roaming\UltraViewer"
		"XMReality"                         = ""
		"Viewabo"                           = ""
		"ZoHo Assist (Dir 1)"               = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\ZohoMeeting"
		"ZoHo Assist (Dir 2)"               = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\GoTo Resolve Applet"
		"ZoHo Assist (Dir 3)"               = "$($State.Drives.HomeDrive)\Program Files (x86)\GoTo Resolve*"
		"ZoHo Assist (Dir 4)"               = "$($State.Drives.HomeDrive)\Users\USER_REPLACE\AppData\Local\GoTo"
	}

	if (Test-Path "$($State.Drives.HomeDrive)\Users") {
		$profile_names = Get-ChildItem "$($State.Drives.HomeDrive)\Users" -Directory | Select-Object *
	}
	else {
		$profile_names = @()
		Write-Warning "[!] Could not find '$($State.Drives.HomeDrive)\Users'!"
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
					foreach ($p in $State.Drives.CurrentUsers) {
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
				foreach ($p in $State.Drives.CurrentUsers) {
					$paths += $checked_path.Replace("HKCU", $p)
				}
			}
			else {
				$paths += $checked_path
			}
		}

		foreach ($tmppath in $paths) {
			if (Test-Path $tmppath) {
				if ($State.IsExemptBySnapShot($rat_name, $tmppath, 'RATS')) {
					continue
				}

				$detection = [TrawlerDetection]::new(
					'Remote Access Tool Artifact',
					[TrawlerRiskPriority]::Medium,
					'Software',
					"T1219: Remote Access Software",
					[PSCustomObject]@{
						PossibleRATArtifact = $rat_name
						Location = $tmppath
					}
				)

				$State.WriteDetection($detection)
			}
		}
	}
}