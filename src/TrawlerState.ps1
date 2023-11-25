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

    TrawlerState() {

    }

    <#
    # Check is a given snapshot exemption table contains the key value pair for the given snapshot.
    # Returns true if the key and value exist in the table, otherwise, returns false
    #>
    [bool] IsExemptBySnapShot([TrawlerSnapShotData]$data) {
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

    TrawlerDetection([string]$name, [TrawlerRiskPriority]$risk, [string]$source, [string]$technique,[object]$metadata) {
        $this.Name = $name
        $this.Risk = $risk
        $this.Source = $source
        $this.Technique = $technique
        $this.Metadata = $metadata
    }
}