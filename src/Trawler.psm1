function Start-Trawler {
    [CmdletBinding()]
    param
    (
        [Parameter(HelpMessage = 'The fully-qualified file-path where detection output should be stored as a CSV, defaults to $PSScriptRoot\detections.csv')]
        [string]
        $OutputPath = "$PSScriptRoot\detections.csv",
        [Parameter(HelpMessage = 'Should a snapshot CSV be generated')]
        [switch]
        $CreateSnapShot,
        [Parameter(HelpMessage = 'Suppress Detection Output to Console')]
        [switch]
        $Quiet,
        [Parameter(HelpMessage = 'The fully-qualified file-path where persistence snapshot output should be stored as a CSV, defaults to $PSScriptRoot\snapshot.csv')]
        [string]
        $SnapShotPath = "$PSScriptRoot\snapshot.csv",
        [Parameter(HelpMessage = 'The fully-qualified file-path where the snapshot CSV to be loaded is located')]
        [string]
        $LoadSnapShot,
        [Parameter(HelpMessage = 'The drive to target for analysis - for example, if mounting an imaged system as a second drive on an analysis device, specify via -drivetarget "D:" (NOT YET IMPLEMENTED)')]
        [string]
        $TargetDrive,
        [Parameter(HelpMessage = "Allows for targeting certain scanners and ignoring others. Use 'All' to run all scanners.")]
        [TrawlerScanOptions]
        $ScanOptions = [TrawlerScanOptions]::All
    )

    $trawlerState = [TrawlerState]::new();
    $trawlerState.Quiet = $Quiet
    $trawlerState.OutputPath = $OutputPath
    $trawlerState.CreateSnapShot = $CreateSnapShot
    $trawlerState.SnapShotPath = $SnapShotPath
    $trawlerState.TargetDrive = $TargetDrive
    $trawlerState.ScanOptions = $ScanOptions

    New-ExecuteScanOptions -State $State

    return $trawlerState
}

function New-ExecuteScanOptions {
    [CmdletBinding()]
    param (
        [Parameter()]
        [TrawlerState]
        $State
    )

    foreach ($option in $State.ScanOptions) {
        switch ($option) {
            [TrawlerScanOptions]::ActiveSetup { Test-ActiveSetup -State $State }
            [TrawlerScanOptions]::AMSIProviders { Test-AMSIProviders -State $State }
            [TrawlerScanOptions]::AppCertDLLs { Test-AppCertDLLs -State $State }
            [TrawlerScanOptions]::AppInitDLLs { Test-AppInitDLLs -State $State }
            [TrawlerScanOptions]::ApplicationShims { Test-ApplicationShims -State $State }
            [TrawlerScanOptions]::AppPaths { Test-AppPaths -State $State }
            [TrawlerScanOptions]::AssociationHijack { Test-Association-Hijack -State $State }
            [TrawlerScanOptions]::AutoDialDLL { Test-AutoDialDLL -State $State }
            [TrawlerScanOptions]::BIDDll { Test-BIDDll -State $State }
            [TrawlerScanOptions]::BITS { Test-BITS -State $State }
            [TrawlerScanOptions]::BootVerificationProgram { Test-BootVerificationProgram -State $State }
            [TrawlerScanOptions]::COMHijacks { Test-COM-Hijacks -State $State }
            [TrawlerScanOptions]::CommandAutoRunProcessors { Test-CommandAutoRunProcessors -State $State }
            [TrawlerScanOptions]::Connections { Test-Connections -State $State }
            [TrawlerScanOptions]::ContextMenu { Test-ContextMenu -State $State }
            [TrawlerScanOptions]::DebuggerHijacks { Test-Debugger-Hijacks -State $State }
            [TrawlerScanOptions]::DNSServerLevelPluginDLL { Test-DNSServerLevelPluginDLL -State $State }
            [TrawlerScanOptions]::DisableLowIL { Test-DisableLowILProcessIsolation -State $State }
            [TrawlerScanOptions]::DiskCleanupHandlers { Test-DiskCleanupHandlers -State $State }
            [TrawlerScanOptions]::eRegChecks { Test-Registry-Checks -State $State }
            [TrawlerScanOptions]::ErrorHandlerCMD { Test-ErrorHandlerCMD -State $State }
            [TrawlerScanOptions]::ExplorerHelperUtilities { Test-ExplorerHelperUtilities -State $State }
            [TrawlerScanOptions]::FolderOpen { Test-FolderOpen -State $State }
            [TrawlerScanOptions]::GPOExtensions { Test-GPOExtensions -State $State }
            [TrawlerScanOptions]::GPOScripts { Test-GPO-Scripts -State $State }
            [TrawlerScanOptions]::HTMLHelpDLL { Test-HTMLHelpDLL -State $State }
            [TrawlerScanOptions]::IFEO { Test-IFEO -State $State }
            [TrawlerScanOptions]::InternetSettingsLUIDll { Test-InternetSettingsLUIDll -State $State }
            [TrawlerScanOptions]::KnownManagedDebuggers { Test-KnownManagedDebuggers -State $State }
            [TrawlerScanOptions]::LNK { Test-LNK -State $State }
            [TrawlerScanOptions]::LSA { Test-LSA -State $State }
            [TrawlerScanOptions]::MicrosoftTelemetryCommands { Test-MicrosoftTelemetryCommands -State $State }
            [TrawlerScanOptions]::ModifiedWindowsAccessibilityFeature { Test-Modified-Windows-Accessibility-Feature -State $State }
            [TrawlerScanOptions]::MSDTCDll { Test-MSDTCDll -State $State }
            [TrawlerScanOptions]::Narrator { Test-Narrator -State $State }
            [TrawlerScanOptions]::NaturalLanguageDevelopmentDLLs { Test-NaturalLanguageDevelopmentDLLs -State $State }
            [TrawlerScanOptions]::NetSHDLLs { Test-NetSHDLLs -State $State }
            [TrawlerScanOptions]::NotepadPPPlugins { Test-Notepad++-Plugins -State $State }
            [TrawlerScanOptions]::OfficeAI { Test-OfficeAI -State $State }
            [TrawlerScanOptions]::OfficeGlobalDotName { Test-OfficeGlobalDotName -State $State }
            [TrawlerScanOptions]::Officetest { Test-Officetest -State $State }
            [TrawlerScanOptions]::OfficeTrustedLocations { Test-Office-Trusted-Locations -State $State }
            [TrawlerScanOptions]::OutlookStartup { Test-Outlook-Startup -State $State }
            [TrawlerScanOptions]::PATHHijacks { Test-PATH-Hijacks -State $State }
            [TrawlerScanOptions]::PeerDistExtensionDll { Test-PeerDistExtensionDll -State $State }
            [TrawlerScanOptions]::PolicyManager { Test-PolicyManager -State $State }
            [TrawlerScanOptions]::PowerShellProfiles { Test-PowerShell-Profiles -State $State }
            [TrawlerScanOptions]::PrintMonitorDLLs { Test-PrintMonitorDLLs -State $State }
            [TrawlerScanOptions]::PrintProcessorDLLs { Test-PrintProcessorDLLs -State $State }
            [TrawlerScanOptions]::Processes { Test-Processes -State $State }
            [TrawlerScanOptions]::ProcessModules { Test-Process-Modules -State $State }
            [TrawlerScanOptions]::RATS { Test-RATS -State $State }
            [TrawlerScanOptions]::RDPShadowConsent { Test-RDPShadowConsent -State $State }
            [TrawlerScanOptions]::RDPStartupPrograms { Test-RDPStartupPrograms -State $State }
            [TrawlerScanOptions]::RemoteUACSetting { Test-RemoteUACSetting -State $State }
            [TrawlerScanOptions]::ScheduledTasks { Test-ScheduledTasks -State $State }
            [TrawlerScanOptions]::ScreenSaverEXE { Test-ScreenSaverEXE -State $State }
            [TrawlerScanOptions]::SEMgrWallet { Test-SEMgrWallet -State $State }
            [TrawlerScanOptions]::ServiceHijacks { Test-Service-Hijacks -State $State }
            [TrawlerScanOptions]::Services { Test-Services -State $State }
            [TrawlerScanOptions]::SethcHijack { Test-SethcHijack -State $State }
            [TrawlerScanOptions]::SilentProcessExitMonitoring { Test-SilentProcessExitMonitoring -State $State }
            [TrawlerScanOptions]::Startups { Test-Startups -State $State }
            [TrawlerScanOptions]::SuspiciousCertificates { Test-Suspicious-Certificates -State $State }
            [TrawlerScanOptions]::SuspiciousFileLocation { Test-Suspicious-File-Locations -State $State }
            [TrawlerScanOptions]::TerminalProfiles { Test-TerminalProfiles -State $State }
            [TrawlerScanOptions]::TerminalServicesDLL { Test-TerminalServicesDLL -State $State }
            [TrawlerScanOptions]::TerminalServicesInitialProgram { Test-TerminalServicesInitialProgram -State $State }
            [TrawlerScanOptions]::TimeProviderDLLs { Test-TimeProviderDLLs -State $State }
            [TrawlerScanOptions]::TrustProviderDLL { Test-TrustProviderDLL -State $State }
            [TrawlerScanOptions]::UninstallStrings { Test-UninstallStrings -State $State }
            [TrawlerScanOptions]::UserInitMPRScripts { Test-UserInitMPRScripts -State $State }
            [TrawlerScanOptions]::Users { Test-Users -State $State }
            [TrawlerScanOptions]::UtilmanHijack { Test-UtilmanHijack -State $State }
            [TrawlerScanOptions]::WellKnownCOM { Test-WellKnownCOM -State $State }
            [TrawlerScanOptions]::WERRuntimeExceptionHandlers { Test-WERRuntimeExceptionHandlers -State $State }
            [TrawlerScanOptions]::WindowsLoadKey { Test-WindowsLoadKey -State $State }
            [TrawlerScanOptions]::WindowsUnsignedFiles { Test-Windows-Unsigned-Files -State $State }
            [TrawlerScanOptions]::WindowsUpdateTestDlls { Test-WindowsUpdateTestDlls -State $State }
            [TrawlerScanOptions]::WinlogonHelperDLLs { Test-WinlogonHelperDLLs -State $State }
            [TrawlerScanOptions]::WMIConsumers { Test-WMIConsumers -State $State }
            [TrawlerScanOptions]::Wow64LayerAbuse { Test-Wow64LayerAbuse -State $State }
            # [TrawlerScanOptions]::RegistryChecks {Test-Registry-Checks}
            # [TrawlerScanOptions]::SCMDACL {Test-SCM-DACL}
        }
    }
}