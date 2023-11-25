<#
	.SYNOPSIS
		trawler helps Incident Responders discover suspicious persistence mechanisms on Windows devices.
	
	.DESCRIPTION
		trawler inspects a wide variety of Windows artifacts to help discover signals of persistence including the registry, scheduled tasks, services, startup items, etc.
        For a full list of artifacts, please see github.com/joeavanzato/trawler

	.PARAMETER outpath
		The fully-qualified file-path where detection output should be stored as a CSV

    .PARAMETER snapshot
		If specified, tells trawler to capture a persistence snapshot

    .PARAMETER hide
		If specified, tells trawler to suppress detection output to console

	.PARAMETER snapshotpath
		The fully-qualified file-path where snapshot output should be stored - defaults to $PSScriptRoot\snapshot.csv

    .PARAMETER loadsnapshot
		The fully-qualified file-path to a previous snapshot to be loaded for allow-listing

	.PARAMETER ScanOptions
		Set to pick specific scanners to run. Multiple can be used when separated by a comma. (Supports tab completion)

	.EXAMPLE
		.\trawler.ps1 -outpath "C:\detections.csv"

	.EXAMPLE
		.\trawler.ps1 -outpath "C:\detections.csv" -ScanOptions ScheduledTasks, BITS
	
	.OUTPUTS
		None
	
	.NOTES
		None
	
	.INPUTS
		None
	
	.LINK
		https://github.com/joeavanzato/Trawler
#>

# TODO - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon - Notify Value - Investigate for value/defaults and add to appropriate Winlogon Helper check [https://github.com/persistence-info/persistence-info.github.io/blob/main/Data/winlogonnotificationpackage.md]



[CmdletBinding()]
param
(
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The fully-qualified file-path where detection output should be stored as a CSV, defaults to $PSScriptRoot\detections.csv')]
	[string]
	$outpath = "$PSScriptRoot\detections.csv",
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Should a snapshot CSV be generated')]
	[switch]
	$snapshot,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Suppress Detection Output to Console')]
	[switch]
	$Quiet,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The fully-qualified file-path where persistence snapshot output should be stored as a CSV, defaults to $PSScriptRoot\snapshot.csv')]
	[string]
	$snapshotpath = "$PSScriptRoot\snapshot.csv",
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The fully-qualified file-path where the snapshot CSV to be loaded is located')]
	[string]
	$loadsnapshot,
	[Parameter(
		Mandatory = $false,
		HelpMessage = 'The drive to target for analysis - for example, if mounting an imaged system as a second drive on an analysis device, specify via -drivetarget "D:" (NOT YET IMPLEMENTED)')]
	[string]
	$drivetarget,
	[Parameter(
		Mandatory = $false,
		HelpMessage = "Allows for targeting certain scanners and ignoring others. Use 'All' to run all scanners.")]
	[ValidateSet(
		"ActiveSetup",
		"All",
		"AMSIProviders",
		"AppCertDLLs",
		"AppInitDLLs",
		"ApplicationShims",
		"AppPaths",
		"AssociationHijack",
		"AutoDialDLL",
		"BIDDll",
		"BITS",
		"BootVerificationProgram",
		"COMHijacks",
		"CommandAutoRunProcessors",
		"Connections",
		"ContextMenu",
		"DebuggerHijacks",
		"DisableLowIL",
		"DiskCleanupHandlers",
		"DNSServerLevelPluginDLL",
		"eRegChecks",
		"ErrorHandlerCMD",
		"ExplorerHelperUtilities",
		"FolderOpen",
		"GPOExtensions",
		"GPOScripts",
		"HTMLHelpDLL",
		"IFEO",
		"InternetSettingsLUIDll",
		"KnownManagedDebuggers",
		"LNK",
		"LSA",
		"MicrosoftTelemetryCommands",
		"ModifiedWindowsAccessibilityFeature",
		"MSDTCDll",
		"Narrator",
		"NaturalLanguageDevelopmentDLLs",
		"NetSHDLLs",
		"NotepadPPPlugins",
		"OfficeAI",
		"OfficeGlobalDotName",
		"Officetest",
		"OfficeTrustedLocations",
		"OutlookStartup",
		"PATHHijacks",
		"PeerDistExtensionDll",
		"PolicyManager",
		"PowerShellProfiles",
		"PrintMonitorDLLs",
		"PrintProcessorDLLs",
		"Processes",
		"ProcessModules",
		"RATS",
		"RDPShadowConsent",
		"RDPStartupPrograms",
		"RegistryChecks",
		"RemoteUACSetting",
		"ScheduledTasks",
		"SCMDACL",
		"ScreenSaverEXE",
		"SEMgrWallet",
		"ServiceHijacks",
		"Services",
		"SethcHijack",
		"SilentProcessExitMonitoring",
		"Startups",
		"SuspiciousCertificates",
		"SuspiciousFileLocation",
		"TerminalProfiles",
		"TerminalServicesDLL",
		"TerminalServicesInitialProgram",
		"TimeProviderDLLs",
		"TrustProviderDLL",
		"UninstallStrings",
		"UserInitMPRScripts",
		"Users",
		"UtilmanHijack",
		"WellKnownCOM",
		"WERRuntimeExceptionHandlers",
		"WindowsLoadKey",
		"WindowsUnsignedFiles",
		"WindowsUpdateTestDlls",
		"WinlogonHelperDLLs",
		"WMIConsumers",
		"Wow64LayerAbuse"
	)]
	$ScanOptions = "All"
)

# TODO - Refactor below into setup function
# Script Level Variable Setup

if ($PSBoundParameters.ContainsKey('loadsnapshot')) {
	$loadsnapshotdata = $true
}
else {
	$loadsnapshotdata = $false
}

if ($PSBoundParameters.ContainsKey('drivetarget')) {
	$drivechange = $true
}
else {
	$drivechange = $false
}

$detection_list = New-Object -TypeName "System.Collections.ArrayList"


function Get-ValidOutPath {
	param (
		[string]
		$path
	)

	if (Test-Path -Path $path -PathType Container) {
		Write-Host "The provided path is a folder, not a file. Please provide a file path." -Foregroundcolor "Yellow"
		exit
	}

	return $path
}

function ValidatePaths {
	try {
		$script:outpath = Get-ValidOutPath -path $outpath
		Write-Message "Detection Output Path: $outpath"
		[System.IO.File]::OpenWrite($outpath).Close()
		$script:output_writable = $true
	}
	catch {
		Write-Warning "Unable to write to provided output path: $outpath"
		$script:output_writable = $false
	}

	if ($snapshot) {
		try {
			$script:snapshotpath = Get-ValidOutPath -path $snapshotpath
			Write-Message "Snapshot Output Path: $snapshotpath"
			[System.IO.File]::OpenWrite($snapshotpath).Close()
			Clear-Content $snapshotpath
			$script:snapshotpath_writable = $true
		}
		catch {
			Write-Warning "Unable to write to provided snapshot path: $snapshotpath"
			$script:snapshotpath_writable = $false
		}
	}
}


# TODO - JSON Detection Output to easily encapsulate more details
# TODO - Non-Standard Service/Task running as/created by Local Administrator
# TODO - Browser Extension Analysis
# TODO - Temporary RID Hijacking
# TODO - ntshrui.dll - https://www.mandiant.com/resources/blog/malware-persistence-windows-registry
# TODO - Add file metadata for detected files (COM/DLL Hijacks, etc)
# TODO - Add more suspicious paths for running processes
# TODO - Iterate through HKEY_USERS when encountering HKEY_CURRENT_USER hive reference


# Snapshot acts as a custom allow-list for a specific gold-image or enterprise environment
# Run trawler once like '.\trawler.ps1 -snapshot' to generate 'snapshot.csv
# $message.key = Lookup component for allow-list hashtable
# $message.value = Lookup component for allow-list hashtable
# $message.source = Where are the K/V sourced from
# TODO - Consider implementing this as JSON instead of CSV for more detailed storage and to easier support in-line modification by other tools



function Assert-IsAllowed($allowmap, $key, $val, $det) {
	if ($allowmap.GetType().Name -eq "Hashtable") {
		if ($allowmap.ContainsKey($key)) {
			if ($allowmap[$key] -eq $val) {
				return $true
			}
			elseif ($allowmap[$key] -eq "" -and ($val -eq $null -or $val -eq "")) {
				return $true
			}
			else {
				Write-Detection $det
				return $false
			}
		}
	}
	elseif ($allowmap.GetType().Name -eq "ArrayList") {
		if ($allowmap.Contains($key) -or $allowmap.Contains($val)) {
			return $true
		}
		else {
			return $false
		}
	}
	else {
		Write-Warning "Invalid AllowMap Type Specified"
	}
}

function Check-AllowList() {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Source,
		[Parameter()]
		[string]
		$Key,
		[Parameter()]
		[string]
		$Value
	)

	$checkList = $AllowData | Where-Object Source -eq $Source

	return $checkList.Key -contains $Key -or $checkList.Value -contains $Value
}

function Check-AllowHashTable() {
	[CmdletBinding()]
	param (
		[Parameter()]
		[Hashtable]
		$Source,
		[Parameter()]
		[string]
		$Key,
		[Parameter()]
		[string]
		$Value,
		[Parameter()]
		[object]
		$Detection
	)

	$checkList = ($AllowData | Where-Object Source -eq $Source) | Where-Object Key -eq $Key | Select-Object * -Unique

	if (!$checkList) {
		return $false
	}

	if ($checkList.Key -eq $Key -and $checkList.Value -eq $Value) {
		return $true 
	}
 else {
		Write-Detection $Detection
		return $false
	}
}

$new_psdrives_list = @{}
function Load-Hive($hive_name, $hive_path, $hive_root) {
	Write-Message "Loading Registry Hive File: $hive_path at location: $hive_root\$hive_name"
	$null = New-PSDrive -PSProvider Registry -Name $hive_name -Root $hive_root
	$reg_fullpath = "$hive_root`\$hive_name"
	$null = reg load $reg_fullpath "$hive_path"
	$new_psdrives_list.Add($reg_fullpath, $hive_name)
}

function Unload-Hive($hive_fullpath, $hive_value) {
	Write-Message "Unloading $hive_fullpath"
	[gc]::collect()
	$null = reg unload $hive_fullpath
	#$null = Remove-PSDrive -Name $hive_value -Root $hive_root
}

function Start-CleanUp {
	#Start-Sleep -seconds 5
	if ($drivechange) {
		foreach ($hive in $new_psdrives_list.GetEnumerator()) {
			$hive_key = $hive.Key
			if (Test-Path "Registry::$hive_key") {
				Unload-Hive $hive.Key $hive.Value
			}
		}
	}
}

$possibleScanOptions = @(
	"ActiveSetup",
	"AMSIProviders",
	"AppCertDLLs",
	"AppInitDLLs",
	"ApplicationShims",
	"AppPaths",
	"AssociationHijack",
	"AutoDialDLL",
	"BIDDll",
	"BITS",
	"BootVerificationProgram",
	"COMHijacks",
	"CommandAutoRunProcessors",
	"Connections",
	"ContextMenu",
	"DebuggerHijacks",
	"DiskCleanupHandlers",
	"DisableLowIL",
	"DNSServerLevelPluginDLL",
	"eRegChecks",
	"ErrorHandlerCMD",
	"ExplorerHelperUtilities",
	"FolderOpen",
	"GPOExtensions",
	"GPOScripts",
	"HTMLHelpDLL",
	"IFEO",
	"InternetSettingsLUIDll",
	"KnownManagedDebuggers",
	"LNK",
	"LSA",
	"MicrosoftTelemetryCommands",
	"ModifiedWindowsAccessibilityFeature",
	"MSDTCDll",
	"Narrator",
	"NaturalLanguageDevelopmentDLLs",
	"NetSHDLLs",
	"NotepadPPPlugins",
	"OfficeAI",
	"OfficeGlobalDotName",
	"Officetest",
	"OfficeTrustedLocations",
	"OutlookStartup",
	"PATHHijacks",
	"PeerDistExtensionDll",
	"PolicyManager",
	"PowerShellProfiles",
	"PrintMonitorDLLs",
	"PrintProcessorDLLs",
	"Processes",
	"ProcessModules",
	"RATS",
	"RDPShadowConsent",
	"RDPStartupPrograms",
	"RegistryChecks",
	"RemoteUACSetting",
	"ScheduledTasks",
	"SCMDACL",
	"ScreenSaverEXE",
	"SEMgrWallet",
	"ServiceHijacks",
	"Services",
	"SethcHijack",
	"SilentProcessExitMonitoring",
	"Startups",
	"SuspiciousCertificates",
	"SuspiciousFileLocation",
	"TerminalProfiles",
	"TerminalServicesDLL",
	"TerminalServicesInitialProgram",
	"TimeProviderDLLs",
	"TrustProviderDLL",
	"UninstallStrings",
	"UserInitMPRScripts",
	"Users",
	"UtilmanHijack",
	"WellKnownCOM",
	"WERRuntimeExceptionHandlers",
	"WindowsLoadKey",
	"WindowsUnsignedFiles",
	"WindowsUpdateTestDlls",
	"WinlogonHelperDLLs",
	"WMIConsumers",
	"Wow64LayerAbuse"
)

function Main {
	Logo
	ValidatePaths
	Drive-Change

	if ($loadsnapshotdata -and $snapshot -eq $false) {
		Read-Snapshot
	}
 elseif ($loadsnapshotdata -and $snapshot) {
		Write-Host "[!] Cannot load and save snapshot simultaneously!" -ForegroundColor "Red"
	}

	if ($ScanOptions -eq "All") {
		$ScanOptions = $possibleScanOptions
	}

	foreach ($option in $ScanOptions) {
		switch ($option) {
			"ActiveSetup" { Check-ActiveSetup }
			"AMSIProviders" { Check-AMSIProviders }
			"AppCertDLLs" { Check-AppCertDLLs }
			"AppInitDLLs" { Check-AppInitDLLs }
			"ApplicationShims" { Check-ApplicationShims }
			"AppPaths" { Check-AppPaths }
			"AssociationHijack" { Check-Association-Hijack }
			"AutoDialDLL" { Check-AutoDialDLL }
			"BIDDll" { Check-BIDDll }
			"BITS" { Check-BITS }
			"BootVerificationProgram" { Check-BootVerificationProgram }
			"COMHijacks" { Check-COM-Hijacks }
			"CommandAutoRunProcessors" { Check-CommandAutoRunProcessors }
			"Connections" { Check-Connections }
			"ContextMenu" { Check-ContextMenu }
			"DebuggerHijacks" { Check-Debugger-Hijacks }
			"DNSServerLevelPluginDLL" { Check-DNSServerLevelPluginDLL }
			"DisableLowIL" { Check-DisableLowILProcessIsolation }
			"DiskCleanupHandlers" { Check-DiskCleanupHandlers }
			"eRegChecks" { Check-Registry-Checks }
			"ErrorHandlerCMD" { Check-ErrorHandlerCMD }
			"ExplorerHelperUtilities" { Check-ExplorerHelperUtilities }
			"FolderOpen" { Check-FolderOpen }
			"GPOExtensions" { Check-GPOExtensions }
			"GPOScripts" { Check-GPO-Scripts }
			"HTMLHelpDLL" { Check-HTMLHelpDLL }
			"IFEO" { Check-IFEO }
			"InternetSettingsLUIDll" { Check-InternetSettingsLUIDll }
			"KnownManagedDebuggers" { Check-KnownManagedDebuggers }
			"LNK" { Check-LNK }
			"LSA" { Check-LSA }
			"MicrosoftTelemetryCommands" { Check-MicrosoftTelemetryCommands }
			"ModifiedWindowsAccessibilityFeature" { Check-Modified-Windows-Accessibility-Feature }
			"MSDTCDll" { Check-MSDTCDll }
			"Narrator" { Check-Narrator }
			"NaturalLanguageDevelopmentDLLs" { Check-NaturalLanguageDevelopmentDLLs }
			"NetSHDLLs" { Check-NetSHDLLs }
			"NotepadPPPlugins" { Check-Notepad++-Plugins }
			"OfficeAI" { Check-OfficeAI }
			"OfficeGlobalDotName" { Check-OfficeGlobalDotName }
			"Officetest" { Check-Officetest }
			"OfficeTrustedLocations" { Check-Office-Trusted-Locations }
			"OutlookStartup" { Check-Outlook-Startup }
			"PATHHijacks" { Check-PATH-Hijacks }
			"PeerDistExtensionDll" { Check-PeerDistExtensionDll }
			"PolicyManager" { Check-PolicyManager }
			"PowerShellProfiles" { Check-PowerShell-Profiles }
			"PrintMonitorDLLs" { Check-PrintMonitorDLLs }
			"PrintProcessorDLLs" { Check-PrintProcessorDLLs }
			"Processes" { Check-Processes }
			"ProcessModules" { Check-Process-Modules }
			"RATS" { Check-RATS }
			"RDPShadowConsent" { Check-RDPShadowConsent }
			"RDPStartupPrograms" { Check-RDPStartupPrograms }
			# "RegistryChecks" {Check-Registry-Checks}  # Deprecated
			"RemoteUACSetting" { Check-RemoteUACSetting }
			"ScheduledTasks" { Check-ScheduledTasks }
			# "SCMDACL" {Check-SCM-DACL} # TODO
			"ScreenSaverEXE" { Check-ScreenSaverEXE }
			"SEMgrWallet" { Check-SEMgrWallet }
			"ServiceHijacks" { Check-Service-Hijacks }
			"Services" { Check-Services }
			"SethcHijack" { Check-SethcHijack }
			"SilentProcessExitMonitoring" { Check-SilentProcessExitMonitoring }
			"Startups" { Check-Startups }
			"SuspiciousCertificates" { Check-Suspicious-Certificates }
			"SuspiciousFileLocation" { Check-Suspicious-File-Locations }
			"TerminalProfiles" { Check-TerminalProfiles }
			"TerminalServicesDLL" { Check-TerminalServicesDLL }
			"TerminalServicesInitialProgram" { Check-TerminalServicesInitialProgram }
			"TimeProviderDLLs" { Check-TimeProviderDLLs }
			"TrustProviderDLL" { Check-TrustProviderDLL }
			"UninstallStrings" { Check-UninstallStrings }
			"UserInitMPRScripts" { Check-UserInitMPRScripts }
			"Users" { Check-Users }
			"UtilmanHijack" { Check-UtilmanHijack }
			"WellKnownCOM" { Check-WellKnownCOM }
			"WERRuntimeExceptionHandlers" { Check-WERRuntimeExceptionHandlers }
			"WindowsLoadKey" { Check-WindowsLoadKey }
			"WindowsUnsignedFiles" { Check-Windows-Unsigned-Files }
			"WindowsUpdateTestDlls" { Check-WindowsUpdateTestDlls }
			"WinlogonHelperDLLs" { Check-WinlogonHelperDLLs }
			"WMIConsumers" { Check-WMIConsumers }
			"Wow64LayerAbuse" { Check-Wow64LayerAbuse }
		}
	}

	Start-CleanUp
	Detection-Metrics
}


if ($MyInvocation.InvocationName -match ".+.ps1") {
	Main
}