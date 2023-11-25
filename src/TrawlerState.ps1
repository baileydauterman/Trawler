enum TrawlerScanOptions {
    <# Specify a list of distinct values #>
    ActiveSetup
    All
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

class TrawlerState {
    <# Define the class. Try constructors, properties, or methods. #>
    [string]$OutputPath = "$PSScriptRoot\trawler_detections.csv"
    [string]$SnapShotPath = "$PSScriptRoot\snapshot.csv"
    [switch]$CreateSnapShot
    [switch]$Quiet
    [string]$LoadSnapShot
    [string]$TargetDrive
    [TrawlerScanOptions[]]$ScanOptions

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

        $csv_data = Import-CSV $this.LoadSnapShot
        $this.AllowedVulns = $csv_data
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
        Write-Message "Total Detections: $($this.Detections.Count)"

        foreach ($str in ($this.Detections | Group-Object Risk | Select-Object Name, Count | Out-String).Split([System.Environment]::NewLine)) {
            if (-not ([System.String]::IsNullOrWhiteSpace($str))) {
                Write-Message $str
            }
        }
    }

    <#
    # Write a snapshot message to the snapshot csv if indicated by user.
    #>
    [void] WriteSnapShotMessage([string]$Key, [string]$Value, [string]$Source) {
        # Only write when writable and snapshot is specified
        if (-not ($this.SnapShotWritable -and $this.CreateSnapShot)) {
            return;
        }

        $snapShot = [TrawlerSnapShotData]::new($key, $value, $source)
        $snapShot | Export-CSV $this.CreateSnapShotPath -Append -NoTypeInformation -Encoding UTF8
    }

    <#
    # Write a snapshot message to the snapshot csv if indicated by user.
    #>
    [void] WriteSnapShotMessage([TrawlerSnapShotData]$snapShotData) {
        # Only write when writable and snapshot is specified
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

    $SuspiciousProcessPaths = @(
        ".*\\users\\administrator\\.*",
        ".*\\users\\default\\.*",
        ".*\\users\\public\\.*",
        ".*\\windows\\debug\\.*",
        ".*\\windows\\fonts\\.*",
        ".*\\windows\\media\\.*",
        ".*\\windows\\repair\\.*",
        ".*\\windows\\servicing\\.*",
        ".*\\windows\\temp\\.*",
        ".*recycle.bin.*"
    )

    $SuspiciousTerms = ".*(\[System\.Reflection\.Assembly\]|regedit|invoke-iex|frombase64|tobase64|rundll32|http:|https:|system\.net\.webclient|downloadfile|downloadstring|bitstransfer|system\.net\.sockets|tcpclient|xmlhttp|AssemblyBuilderAccess|shellcode|rc4bytestream|disablerealtimemonitoring|wmiobject|wmimethod|remotewmi|wmic|gzipstream|::decompress|io\.compression|write-zip|encodedcommand|wscript\.shell|MSXML2\.XMLHTTP).*"
    $IPv4Pattern = '.*((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*'
    $IPv6Pattern = '.*:(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:)).*'
    $OfficeAddInExtensions = ".wll", ".xll", ".ppam", ".ppa", ".dll", ".vsto", ".vba", ".xlam", ".com", ".xla"
    $RatTerms = @(
        #Remote Access Tool Indicators
        # Any Process Name, Scheduled Task or Service containing these keywords will be flagged.
        "aeroadmin",
        "action1"
        "ammyadmin"
        "aa_v"
        "anydesk"
        "anyscreen"
        "anyviewer"
        "atera"
        "aweray_remote"
        "awrem32"
        "awhost32"
        "beyondtrust"
        "bomgar"
        "connectwise"
        "cservice"
        "dameware"
        "desktopnow"
        "distant-desktop"
        "dwservice"
        "dwagent"
        "dwagsvc"
        "dwrcs"
        "famitrfc"
        "g2comm"
        "g2host"
        "g2fileh"
        "g2mainh"
        "g2printh"
        "g2svc"
        "g2tray"
        "gopcsrv"
        "getscreen"
        "iperius"
        "kaseya"
        "litemanager"
        "logmein"
        "lmiignition"
        "lmiguardiansvc"
        "meshagent"
        "mstsc"
        "ninja1"
        "ninjaone"
        "PCMonitorManager"
        "pcmonitorsrv"
        "pulseway"
        "quickassist"
        "radmin"
        "rcclient"
        "realvnc"
        "remotepc"
        "remotetopc"
        "remote utilities"
        "RepairTech"
        "ROMServer"
        "ROMFUSClient"
        "rutserv"
        "screenconnect"
        "screenmeet"
        "showmypc"
        "smpcsetup"
        "strwinclt"
        "supremo"
        "sightcall"
        "splashtop"
        "surfly"
        "syncro"
        "tacticalrmm"
        "teamviewer"
        "tightvnc"
        "ultraviewer"
        "vnc"
        "winvnc"
        "vncviewer"
        "winvncsc"
        "winwvc"
        "xmreality"
        "ultravnc"
        "Zaservice"
        "Zohours"
        "ZohoMeeting"
        "zoho"
    )
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