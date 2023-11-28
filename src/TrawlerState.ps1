enum TrawlerScanOptions {
    <# Specify a list of distinct values #>
    None
    All
    ActiveSetup
    AMSIProviders
    AppCertDLLs
    AppInitDLLs
    ApplicationShims
    AppPaths
    AssociationHijack
    AutoDialDLL
    BIDDll
    BITS
    BootVerificationProgram
    COMHijacks
    CommandAutoRunProcessors
    Connections
    ContextMenu
    DebuggerHijacks
    DisableLowIL
    DiskCleanupHandlers
    DNSServerLevelPluginDLL
    eRegChecks
    ErrorHandlerCMD
    ExplorerHelperUtilities
    FolderOpen
    GPOExtensions
    GPOScripts
    HTMLHelpDLL
    IFEO
    InternetSettingsLUIDll
    KnownManagedDebuggers
    LNK
    LSA
    MicrosoftTelemetryCommands
    ModifiedWindowsAccessibilityFeature
    MSDTCDll
    Narrator
    NaturalLanguageDevelopmentDLLs
    NetSHDLLs
    NotepadPPPlugins
    OfficeAI
    OfficeGlobalDotName
    Officetest
    OfficeTrustedLocations
    OutlookStartup
    PATHHijacks
    PeerDistExtensionDll
    PolicyManager
    PowerShellProfiles
    PrintMonitorDLLs
    PrintProcessorDLLs
    Processes
    ProcessModules
    RATS
    RDPShadowConsent
    RDPStartupPrograms
    RegistryChecks
    RemoteUACSetting
    ScheduledTasks
    SCMDACL
    ScreenSaverEXE
    SEMgrWallet
    ServiceHijacks
    Services
    SethcHijack
    SilentProcessExitMonitoring
    Startups
    SuspiciousCertificates
    SuspiciousFileLocation
    TerminalProfiles
    TerminalServicesDLL
    TerminalServicesInitialProgram
    TimeProviderDLLs
    TrustProviderDLL
    UninstallStrings
    UserInitMPRScripts
    Users
    UtilmanHijack
    WellKnownCOM
    WERRuntimeExceptionHandlers
    WindowsLoadKey
    WindowsUnsignedFiles
    WindowsUpdateTestDlls
    WinlogonHelperDLLs
    WMIConsumers
    Wow64LayerAbuse
}

enum TrawlerRiskPriority {
    VeryLow
    Low
    Medium
    High
    VeryHigh
}

enum TrawlerTechniques {
    None
    All
    NoTechnique
    T1037
    T1053
    T1055
    T1059
    T1071
    T1098
    T1112
    T1136
    T1137
    T1197
    T1219
    T1484
    T1505
    T1543
    T1546
    T1547
    T1553
    T1574
}

class TrawlerState {
    <# Define the class. Try constructors, properties, or methods. #>
    [string]$UserDataPath
    [string]$OutputPath
    [string]$SnapShotPath
    [switch]$CreateSnapShot
    [switch]$Quiet
    [string]$LoadSnapShot
    [string]$TargetDrive = "C:"
    [TrawlerScanOptions[]]$ScanOptions
    [TrawlerTechniques[]]$TechniqueOptions

    TrawlerState() {
        $this.UserDataPath = "$($env:USERPROFILE)\.trawler"
        $this.OutputPath = "$($this.UserDataPath)\trawler_detections.csv"
        $this.SnapShotPath = "$($this.UserDataPath)\snapshot.csv"
    }

    [void] Run() {
        $this.Logo()
        $this.ValidatePaths()
        $this.RetargetDrives()
        $this.ExecuteScanOptions()
        $this.ExecuteTechniqueOptions()
        $this.WriteDetectionMetrics()
        $this.Cleanup()
    }

    <#
    # Executes the given scan options and passes this state into the options
    #>
    [void] ExecuteScanOptions() {
        if ([TrawlerScanOptions]::None -in $this.ScanOptions) {
            return
        }

        if ([TrawlerScanOptions]::All -in $this.ScanOptions) {
            # will skip none and all because they are not cases in the switch statement
            $this.ScanOptions = [TrawlerScanOptions].GetEnumValues()
        }

        foreach ($option in $this.ScanOptions) {
            switch ($option) {
                [TrawlerScanOptions]::ActiveSetup { Test-ActiveSetup -State $this }
                [TrawlerScanOptions]::AMSIProviders { Test-AMSIProviders -State $this }
                [TrawlerScanOptions]::AppCertDLLs { Test-AppCertDLLs -State $this }
                [TrawlerScanOptions]::AppInitDLLs { Test-AppInitDLLs -State $this }
                [TrawlerScanOptions]::ApplicationShims { Test-ApplicationShims -State $this }
                [TrawlerScanOptions]::AppPaths { Test-AppPaths -State $this }
                [TrawlerScanOptions]::AssociationHijack { Test-Association-Hijack -State $this }
                [TrawlerScanOptions]::AutoDialDLL { Test-AutoDialDLL -State $this }
                [TrawlerScanOptions]::BIDDll { Test-BIDDll -State $this }
                [TrawlerScanOptions]::BITS { Test-BITS -State $this }
                [TrawlerScanOptions]::BootVerificationProgram { Test-BootVerificationProgram -State $this }
                [TrawlerScanOptions]::COMHijacks { Test-COM-Hijacks -State $this }
                [TrawlerScanOptions]::CommandAutoRunProcessors { Test-CommandAutoRunProcessors -State $this }
                [TrawlerScanOptions]::Connections { Test-Connections -State $this }
                [TrawlerScanOptions]::ContextMenu { Test-ContextMenu -State $this }
                [TrawlerScanOptions]::DebuggerHijacks { Test-Debugger-Hijacks -State $this }
                [TrawlerScanOptions]::DNSServerLevelPluginDLL { Test-DNSServerLevelPluginDLL -State $this }
                [TrawlerScanOptions]::DisableLowIL { Test-DisableLowILProcessIsolation -State $this }
                [TrawlerScanOptions]::DiskCleanupHandlers { Test-DiskCleanupHandlers -State $this }
                [TrawlerScanOptions]::eRegChecks { Test-Registry-Checks -State $this }
                [TrawlerScanOptions]::ErrorHandlerCMD { Test-ErrorHandlerCMD -State $this }
                [TrawlerScanOptions]::ExplorerHelperUtilities { Test-ExplorerHelperUtilities -State $this }
                [TrawlerScanOptions]::FolderOpen { Test-FolderOpen -State $this }
                [TrawlerScanOptions]::GPOExtensions { Test-GPOExtensions -State $this }
                [TrawlerScanOptions]::GPOScripts { Test-GPO-Scripts -State $this }
                [TrawlerScanOptions]::HTMLHelpDLL { Test-HTMLHelpDLL -State $this }
                [TrawlerScanOptions]::IFEO { Test-IFEO -State $this }
                [TrawlerScanOptions]::InternetSettingsLUIDll { Test-InternetSettingsLUIDll -State $this }
                [TrawlerScanOptions]::KnownManagedDebuggers { Test-KnownManagedDebuggers -State $this }
                [TrawlerScanOptions]::LNK { Test-LNK -State $this }
                [TrawlerScanOptions]::LSA { Test-LSA -State $this }
                [TrawlerScanOptions]::MicrosoftTelemetryCommands { Test-MicrosoftTelemetryCommands -State $this }
                [TrawlerScanOptions]::ModifiedWindowsAccessibilityFeature { Test-Modified-Windows-Accessibility-Feature -State $this }
                [TrawlerScanOptions]::MSDTCDll { Test-MSDTCDll -State $this }
                [TrawlerScanOptions]::Narrator { Test-Narrator -State $this }
                [TrawlerScanOptions]::NaturalLanguageDevelopmentDLLs { Test-NaturalLanguageDevelopmentDLLs -State $this }
                [TrawlerScanOptions]::NetSHDLLs { Test-NetSHDLLs -State $this }
                [TrawlerScanOptions]::NotepadPPPlugins { Test-Notepad++-Plugins -State $this }
                [TrawlerScanOptions]::OfficeAI { Test-OfficeAI -State $this }
                [TrawlerScanOptions]::OfficeGlobalDotName { Test-OfficeGlobalDotName -State $this }
                [TrawlerScanOptions]::Officetest { Test-Officetest -State $this }
                [TrawlerScanOptions]::OfficeTrustedLocations { Test-Office-Trusted-Locations -State $this }
                [TrawlerScanOptions]::OutlookStartup { Test-Outlook-Startup -State $this }
                [TrawlerScanOptions]::PATHHijacks { Test-PATH-Hijacks -State $this }
                [TrawlerScanOptions]::PeerDistExtensionDll { Test-PeerDistExtensionDll -State $this }
                [TrawlerScanOptions]::PolicyManager { Test-PolicyManager -State $this }
                [TrawlerScanOptions]::PowerShellProfiles { Test-PowerShell-Profiles -State $this }
                [TrawlerScanOptions]::PrintMonitorDLLs { Test-PrintMonitorDLLs -State $this }
                [TrawlerScanOptions]::PrintProcessorDLLs { Test-PrintProcessorDLLs -State $this }
                [TrawlerScanOptions]::Processes { Test-Processes -State $this }
                [TrawlerScanOptions]::ProcessModules { Test-ProcessModules -State $this }
                [TrawlerScanOptions]::RATS { Test-RATS -State $this }
                [TrawlerScanOptions]::RDPShadowConsent { Test-RDPShadowConsent -State $this }
                [TrawlerScanOptions]::RDPStartupPrograms { Test-RDPStartupPrograms -State $this }
                [TrawlerScanOptions]::RemoteUACSetting { Test-RemoteUACSetting -State $this }
                [TrawlerScanOptions]::ScheduledTasks { Test-ScheduledTasks -State $this }
                [TrawlerScanOptions]::ScreenSaverEXE { Test-ScreenSaverEXE -State $this }
                [TrawlerScanOptions]::SEMgrWallet { Test-SEMgrWallet -State $this }
                [TrawlerScanOptions]::ServiceHijacks { Test-Service-Hijacks -State $this }
                [TrawlerScanOptions]::Services { Test-Services -State $this }
                [TrawlerScanOptions]::SethcHijack { Test-SethcHijack -State $this }
                [TrawlerScanOptions]::SilentProcessExitMonitoring { Test-SilentProcessExitMonitoring -State $this }
                [TrawlerScanOptions]::Startups { Test-Startups -State $this }
                [TrawlerScanOptions]::SuspiciousCertificates { Test-Suspicious-Certificates -State $this }
                [TrawlerScanOptions]::SuspiciousFileLocation { Test-Suspicious-File-Locations -State $this }
                [TrawlerScanOptions]::TerminalProfiles { Test-TerminalProfiles -State $this }
                [TrawlerScanOptions]::TerminalServicesDLL { Test-TerminalServicesDLL -State $this }
                [TrawlerScanOptions]::TerminalServicesInitialProgram { Test-TerminalServicesInitialProgram -State $this }
                [TrawlerScanOptions]::TimeProviderDLLs { Test-TimeProviderDLLs -State $this }
                [TrawlerScanOptions]::TrustProviderDLL { Test-TrustProviderDLL -State $this }
                [TrawlerScanOptions]::UninstallStrings { Test-UninstallStrings -State $this }
                [TrawlerScanOptions]::UserInitMPRScripts { Test-UserInitMPRScripts -State $this }
                [TrawlerScanOptions]::Users { Test-Users -State $this }
                [TrawlerScanOptions]::UtilmanHijack { Test-UtilmanHijack -State $this }
                [TrawlerScanOptions]::WellKnownCOM { Test-WellKnownCOM -State $this }
                [TrawlerScanOptions]::WERRuntimeExceptionHandlers { Test-WERRuntimeExceptionHandlers -State $this }
                [TrawlerScanOptions]::WindowsLoadKey { Test-WindowsLoadKey -State $this }
                [TrawlerScanOptions]::WindowsUnsignedFiles { Test-Windows-Unsigned-Files -State $this }
                [TrawlerScanOptions]::WindowsUpdateTestDlls { Test-WindowsUpdateTestDlls -State $this }
                [TrawlerScanOptions]::WinlogonHelperDLLs { Test-WinlogonHelperDLLs -State $this }
                [TrawlerScanOptions]::WMIConsumers { Test-WMIConsumers -State $this }
                [TrawlerScanOptions]::Wow64LayerAbuse { Test-Wow64LayerAbuse -State $this }
                # [TrawlerScanOptions]::RegistryChecks {Test-Registry-Checks}
                # [TrawlerScanOptions]::SCMDACL {Test-SCM-DACL}
            }
        }
    }

    <#
    # Execute the given techniques
    #>
    [void] ExecuteTechniqueOptions() {
        if ([TrawlerTechniques]::None -in $this.TechniqueOptions) {
            return
        }

        if ([TrawlerTechniques]::All -in $this.TechniqueOptions) {
            # will skip none and all because they are not cases in the switch statement
            $this.TechniqueOptions = [TrawlerTechniques].GetEnumValues()
        }

        foreach ($option in $this.TechniqueOptions) {
            switch ($option) {
                [TrawlerTechniques]::NoTechnique { Test-NoTechnique - State $this }
                [TrawlerTechniques]::T1037 { Test-T1037 -State $this }
                [TrawlerTechniques]::T1053 { Test-T1053 -State $this }
                [TrawlerTechniques]::T1055 { Test-T1055 -State $this }
                [TrawlerTechniques]::T1059 { Test-T1059 -State $this }
                [TrawlerTechniques]::T1071 { Test-T1071 -State $this }
                [TrawlerTechniques]::T1098 { Test-T1098 -State $this }
                [TrawlerTechniques]::T1112 { Test-T1112 -State $this }
                [TrawlerTechniques]::T1136 { Test-T1136 -State $this }
                [TrawlerTechniques]::T1137 { Test-T1137 -State $this }
                [TrawlerTechniques]::T1197 { Test-T1197 -State $this }
                [TrawlerTechniques]::T1219 { Test-T1219 -State $this }
                [TrawlerTechniques]::T1484 { Test-T1484 -State $this }
                [TrawlerTechniques]::T1505 { Test-T1505 -State $this }
                [TrawlerTechniques]::T1543 { Test-T1543 -State $this }
                [TrawlerTechniques]::T1546 { Test-T1546 -State $this }
                [TrawlerTechniques]::T1547 { Test-T1547 -State $this }
                [TrawlerTechniques]::T1553 { Test-T1553 -State $this }
                [TrawlerTechniques]::T1574 { Test-T1574 -State $this }
            }
        }
    }

    <#
    # Validate the output and snapshot paths. Will exit on failure to validate
    #>
    [void] ValidatePaths() {
        if (-not (Test-Path $this.UserDataPath)) {
            New-Item $this.UserDataPath | Out-Null
        }

        if (ValidatePath($this.OutputPath)) {
            $this.WriteMessage("Detection Output Path: $($this.OutputPath)")
            $this.OutputWritable = $true
        }
        else {
            $this.WriteMessage("Unable to write to provided output path: $($this.OutputPath)")
            exit
        }

        if (ValidatePath($this.SnapShotPath)) {
            $this.WriteMessage("SnapShot Output Path: $($this.OutputPath)")
            $this.OutputWritable = $true
        }
        else {
            $this.WriteMessage("Unable to write to provided SnapShot path: $($this.OutputPath)")
            exit
        }
    }

    <#
    # Try to create 
    #>
    [bool] ValidatePath([string]$path) {
        if (Test-Path -Path $path -PathType Container) {
            return $false
        }

        [System.IO.File]::OpenWrite($path).Close()
        return $true
    }

    <#
    # Loads the snapshot data into the allow vulnerabilities
    #>
    [void] LoadSnapShot() {
        if ($this.LoadSnapShot -and $this.CreateSnapShot) {
            Write-Host "[!] Cannot load and save snapshot simultaneously!" -ForegroundColor "Red"
        }
        elseif ($this.LoadSnapShot) {
            $this.TryReadSnapShot()
        }
    }

    <#
    # Offload loaded hives
    #>
    [void] Cleanup() {
        $this.UnloadHive()
    }

    <#
    # Retarget drives
    #>
    [void] RetargetDrives() {
        $this.WriteMessage("Setting up Registry Variables")

        if ($this.TargetDrive -and ($this.TargetDrive -match "^[A-Za-z]{1}:$")) {
            $this.WriteMessage("[!] Attempting move Target Drive to $($this.TargetDrive)")

            if (-not (Get-ChildItem $this.TargetDrive -Directory -Filter "Windows")) {
                Write-Warning "[!] Could not find Windows Directory in Specified Target Path ($($this.TargetDrive))!"
                $this.WriteMessage("Make sure to specify ROOT directory containing imaged data (eg. 'F:')")
                exit
            }

            $this.DriveTargets.HomeDrive = $this.TargetDrive
            $this.DriveTargets.AssumedHomeDrive = "C:"
            $this.ProgramData = $this.ToTargetDrivePath(@("ProgramData"))

            foreach ($hive in $this.DriveTargets.TargetHives) {
                $hivePath = $this.ToTargetDrivePath(@("Windows", "System32", "Config", $hive))

                if (Test-Path -Path $hivePath) {
                    $this.LoadHive("ANALYSIS_$hive", $hivePath, "HKEY_LOCAL_MACHINE")
                }
            }

            $userPath = $this.ToTargetDrivePath(@("Users"))
            if (Test-Path $userPath) {
                foreach ($user in Get-ChildItem $userPath -Directory) {
                    $ntUserPath = $this.ToTargetDrivePath(@("Users", $user.Name, "NTUSER.DAT"))
                    $classPath = $this.ToTargetDrivePath(@("Users", $user.Name, "AppData", "Local", "Microsoft", "Windows", "UsrClass.DAT"))

                    if (Test-Path $ntUserPath) {
                        $hivePath = "ANALYSIS_$($user.Name)"
                        $this.LoadHive($hivePath, $ntUserPath, "HKEY_USERS")
                        $this.DriveTargets.HkcuList += "HKEY_USERS\$hivePath"
                    }

                    if (Test-Path $classPath) {
                        $hivePath = "ANALYSIS_$($user.Name)_Classes"
                        $this.LoadHive($hivePath, $ntUserPath, "HKEY_USERS")
                        $this.DriveTargets.HkcuList += "HKEY_USERS\$hivePath"
                    }
                }
            }
            else {
                Write-Warning "[!] Could not find '$($this.DriveTargets.HomeDrive)\Users'!"
            }

            $this.DriveTargets.Hklm = "HKEY_LOCAL_MACHINE\ANALYSIS_"
            $this.DriveTargets.Hkcu = "HKEY_CURRENT_USER\"
            # Need to avoid using HKCR as it will be unavailable on dead drives
            $this.DriveTargets.Hkcr = "HKEY_CLASSES_ROOT\"
            $this.DriveTargets.CurrentControlSet = "ControlSet001"
        }
        else {
            foreach ($item in Get-TrawlerChildItem -Path $this.PathAsRegistry("HKEY_USERS")) {
                if ($item.Name -match ".*_Classes") {
                    $this.DriveTargets.HkcuClassList += $item.Name
                }
                else {
                    $this.DriveTargets.HkcuList += $item.Name
                }
            }

            $this.DriveTargets.HomeDrive = $env:homedrive
            $this.DriveTargets.AssumedHomeDrive = $env:homedrive
            $this.DriveTargets.ProgramData = $env:programdata
            $this.DriveTargets.Hklm = "HKEY_LOCAL_MACHINE\"
            $this.DriveTargets.Hkcu = "HKEY_CURRENT_USER\"
            # Need to avoid using HKCR as it will be unavailable on dead drives
            $this.DriveTargets.Hkcr = "HKEY_CLASSES_ROOT\"
            $this.DriveTargets.CurrentControlSet = "CurrentControlSet"
        }
    }

    <#
    # Converts the given path segments into a proper file path starting with the target drive path.
    #>
    [string] ToTargetDrivePath([string[]]$pathSegments) {
        return [System.IO.Path]::Combine($this.DriveTargets.HomeDrive, $pathSegments)
    }

    [void] LoadHive([string]$hiveName, [string]$hivePath, [string]$hiveRoot) {
        $this.WriteMessage("Loading Registry Hive File: $hivePath at location: $hiveRoot\$hiveName")
        New-PSDrive -PSProvider Registry -Name $hiveName -Root $hiveRoot | Out-Null
        $fullPath = "$hiveRoot\$hiveName"
        reg load $fullPath "$hivePath" | Out-Null
        $this.LoadedHives.Add($fullPath, $hiveName)
    }

    [void] UnloadHive() {
        foreach ($hive in $this.LoadedHives) {
            if (Test-Path -Path $this.PathAsRegistry($hive.Key)) {
                $this.WriteMessage("Unloading $(hive.Key)")
                [gc]::collect()
                reg unload $hive.Key | Out-Null
            }
        }
    }

    <#
    # Check is a given snapshot exemption table contains the key value pair for the given snapshot.
    # Returns true if the key and value exist in the table, otherwise, returns false
    #>
    [bool] IsExemptBySnapShot([TrawlerSnapShotData]$data, [switch]$writeSnapShot) {
        if (-not $this.LoadSnapShot) {
            return $false
        }

        if ($writeSnapShot) {
            $this.WriteSnapShotMessage($data)
        }

        $exemptionsTable = $this.AllowedVulns.($data.Source)
        $exemption = $exemptionsTable[$data.Key]
        
        return $exemption -eq $data.Value
    }

    <#
    # Load a snapshot into the state. Snapshot data is saved to [TrawlerState]::AllowedVulns
    # Returns true if able to successfully load the snapshot, otherwise, returns false
    #>
    [bool] TryReadSnapShot() {
        $this.WriteMessage("Reading Snapshot File: $($this.LoadSnapShot)")

        if (-not(Test-Path $this.LoadSnapShot)) {
            Write-Host "[!] Specified snapshot file does not exist!" -ForegroundColor "Yellow"
            return $false
        }

        $this.AllowedVulns = Import-Csv $this.LoadSnapShot
        return $true
    }

    <#
    # Add detection to list of dections and write it out to console if specified by user
    #>
    [void] WriteDetection([TrawlerDetection]$det) {
        $this.Detections.Add($det) | Out-Null

        $fg_color = "Yellow"
        switch ($det.Risk) {
            [TrawlerRiskPriority]::VeryLow { $fg_color = "Green" }
            [TrawlerRiskPriority]::Low { $fg_color = "Green" }
            [TrawlerRiskPriority]::Medium { $fg_color = "Yellow" }
            [TrawlerRiskPriority]::High { $fg_color = "Red" }
            [TrawlerRiskPriority]::VeryHigh { $fg_color = "Magenta" }
        }

        if (-not($this.Quiet)) {
            Write-Host "[!] Detection: $($det.Name) - Risk: $($det.Risk)" -ForegroundColor $fg_color
            Write-Host "[%] $($det.Meta)" -ForegroundColor White
        }

        if ($this.OutputWritable) {
            $det | Export-CSV $this.OutputPath -Append -NoTypeInformation -Encoding UTF8
        }
    }

    <#
    # Output overall statistics of detections
    #>
    [void] WriteDetectionMetrics() {
        Write-Host "[!] ### Detection Metadata ###" -ForeGroundColor White
        $this.WriteMessage("Total Detections: $($this.Detections.Count)")

        foreach ($str in ($this.Detections | Group-Object Risk | Select-Object Name, Count | Out-String).Split([System.Environment]::NewLine)) {
            if (-not ([System.String]::IsNullOrWhiteSpace($str))) {
                $this.WriteMessage($str)
            }
        }
    }

    <#
    # Write a snapshot message to the snapshot csv if indicated by user.
    #>
    [void] WriteSnapShotMessage([string]$Key, [string]$Value, [string]$Source) {
        $snapShot = [TrawlerSnapShotData]::new($key, $value, $source)
        $this.WriteSnapShotMessage($snapShot)
    }

    <#
    # Write a snapshot message to the snapshot csv if indicated by user.
    #>
    [void] WriteSnapShotMessage([TrawlerSnapShotData]$snapShotData) {
        if (-not ($this.SnapShotWritable -and $this.CreateSnapShot)) {
            return;
        }

        $snapShotData | Export-CSV $this.CreateSnapShotPath -Append -NoTypeInformation -Encoding UTF8
    }

    <#
    # Write a warning and instruct user to generate github issue
    #>
    [void] WriteReportableMessage([string]$message, [string]$additionalInformation) {
        Write-Warning $Message

        if ($additionalInformation) {
            Write-Warning "`t$additionalInformation"
        }

        Write-Warning "Please report this issue at https://github.com/joeavanzato/Trawler/issues."
        Write-Warning "`tInformation is valuable so please try to provide as much as possible"
    }

    <#
    # Convert a given path to a registry
    #>
    [string] PathAsRegistry([string]$path) {
        return "Registry::$path"
    }

    <#
    # Write out a message from Trawler
    #>
    [void] WriteMessage([string]$message) {
        Write-Host "[+] $message"
    }

    <#
    # Display the logo in the console
    #>
    [void] WriteLogo() {
        $logo = "
  __________  ___ _       ____    __________ 
 /_  __/ __ \/   | |     / / /   / ____/ __ \
  / / / /_/ / /| | | /| / / /   / __/ / /_/ /
 / / / _, _/ ___ | |/ |/ / /___/ /___/ _, _/ 
/_/ /_/ |_/_/  |_|__/|__/_____/_____/_/ |_|  
    "
        Write-Host $logo -ForegroundColor White
        Write-Host "Trawler - Dredging Windows for Persistence" -ForegroundColor White
        Write-Host "github.com/joeavanzato/trawler" -ForegroundColor White
        Write-Host ""
    }

    $Detections = [System.Collections.ArrayList]::new()
    $OutputWritable = (Test-Path $this.OutputPath)
    $SnapShotWritable = (Test-Path $this.SnapShotPath)
    $AllowedVulns
    $DriveTargets = [PSCustomObject]@{
        HomeDrive         = ""
        AssumedHomeDrive  = "C:"
        ProgramData       = ""
        TargetHives       = @(
            "SOFTWARE"
            "SYSTEM"
        )
        UserHives         = @()
        HkcuList          = @()
        HkcuClassList     = @()
        Hklm              = ""
        Hkcu              = ""
        Hkcr              = ""
        CurrentControlSet = ""
    }
    $LoadedHives = @{}
}

class TrawlerSnapShotData {
    <# Define the class. Try constructors, properties, or methods. #>
    [string]$Key
    [string]$Value
    [string]$Source

    TrawlerSnapShotData([string]$key, [string]$value, [string]$source) {
        $this.Key = $key
        $this.Value = $value
        $this.Source = $source
    }
}

class TrawlerDetection {
    [string]$Name
    [TrawlerRiskPriority]$Risk
    [string]$Source
    [string]$Technique
    [object]$Metadata

    TrawlerDetection([string]$name, [TrawlerRiskPriority]$risk, [string]$source, [string]$technique, [object]$metadata) {
        $this.Name = $name
        $this.Risk = $risk
        $this.Source = $source
        $this.Technique = $technique
        $this.Metadata = $metadata
    }
}