function Test-T1053 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $State
    )

    Test-ScheduledTasks $State
}

function Test-ScheduledTasks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $State
    )

    $State.WriteMessage("Checking Scheduled Tasks")
    $task_base_path = "$($State.Drives.HomeDrive)\Windows\System32\Tasks"
        
    if (-not (Test-Path $task_base_path)) {
        $State.WriteMessage("Could not find Scheduled Task Path: $task_base_path")
        return
    }

    foreach ($item in Get-ChildItem -Path $task_base_path -Recurse -File -ErrorAction SilentlyContinue) {
        $content = Get-Content $item.FullName -ErrorAction SilentlyContinue
        $content = [string]::join("", ($ItemContent.Split("`n")))

        if ([string]::IsNullOrWhiteSpace($content)) {
            continue
        }

        $task = Assert-TaskMatchesRegex -ItemName $item.Name -ItemContent $content

        if (-not $task.IsMatch) {
            continue
        }

        # Allowlist Logic
        if ($State.IsExemptBySnapShot($task.TaskName, $task.Execute, "Scheduled Tasks")) {
            continue
        }

        $TaskDefaults = Build-ScheduledTaskDefaults -State $State

        # Detection - Non-Standard Tasks
        foreach ($i in $TaskDefaults.ExecutablePaths) {
            if ($task.Execute -like $i) {
                $exe_match = $true
                break
            }
            elseif ($task.Execute.Length -gt 0) { 
                $exe_match = $false 
            }
        }

        if (Test-RemoteAccessTrojanTerms -Value $task.Execute -or Test-RemoteAccessTrojanTerms -Value $task.Arguments) {
            # Service has a suspicious launch pattern matching a known RAT
            $detection = [TrawlerDetection]::new(
                'Scheduled Task has known-RAT Keyword',
                [TrawlerRiskPriority]::Medium,
                'Scheduled Tasks',
                "T1053: Scheduled Task/Job",
                $task
            )

            $State.WriteDetection($detection)
        }

        # Task Running as SYSTEM
        if ($task.RunAs -eq "SYSTEM" -and $exe_match -eq $false -and $task.Arguments -notin $default_task_args) {
            # Current Task Executable Path is non-standard
            $detection = [TrawlerDetection]::new(
                'Non-Standard Scheduled Task Running as SYSTEM',
                [TrawlerRiskPriority]::High,
                'Scheduled Tasks',
                "T1053: Scheduled Task/Job",
                $task
            )

            $State.WriteDetection($detection)
            continue
        }
        
        # Detection - Task contains an IP Address
        if (Test-IPAddress -Value $task.Execute) {
            # Task Contains an IP Address
            $detection = [TrawlerDetection]::new(
                'Scheduled Task contains an IP Address',
                [TrawlerRiskPriority]::High,
                'Scheduled Tasks',
                "T1053: Scheduled Task/Job",
                $task
            )

            $State.WriteDetection($detection)
        }
        # TODO - Task contains domain-pattern

        # Task has suspicious terms
        $suspicious_keyword_regex = ".*(regsvr32.exe | downloadstring | mshta | frombase64 | tobase64 | EncodedCommand | DownloadFile | certutil | csc.exe | ieexec.exe | wmic.exe).*"
        if ($task.Execute -match $suspicious_keyword_regex -or $task.Arguments -match $suspicious_keyword_regex) {
            $detection = [TrawlerDetection]::new(
                'Scheduled Task contains suspicious keywords',
                [TrawlerRiskPriority]::High,
                'Scheduled Tasks',
                "T1053: Scheduled Task/Job",
                $task
            )

            $State.WriteDetection($detection)
        }
        
        # Detection - User Created Tasks
        if ($task.Author) {
            if (($task.Author).Contains("\")) {
                if ((($task.Author.Split('\')).count - 1) -eq 1) {
                    if ($task.RunAs -match "SYSTEM") {
                        # Current Task Executable Path is non-standard
                        $detection = [TrawlerDetection]::new(
                            'User-Created Task running as SYSTEM',
                            [TrawlerRiskPriority]::High,
                            'Scheduled Tasks',
                            "T1053: Scheduled Task/Job",
                            $task
                        )

                        $State.WriteDetection($detection)
                    }
                    else {
                        # Single '\' in author most likely indicates it is a user-made task
                        $detection = [TrawlerDetection]::new(
                            'User Created Task',
                            [TrawlerRiskPriority]::Low,
                            'Scheduled Tasks',
                            "T1053: Scheduled Task/Job",
                            $task
                        )

                        $State.WriteDetection($detection)
                    }

                }
            }
        }

        # Non-Standard EXE Path with Non-Default Arguments
        if ($exe_match -eq $false -and $task.Arguments -notin $TaskDefaults.Arguments) {
            # Current Task Executable Path is non-standard
            $detection = [TrawlerDetection]::new(
                'Non-Standard Scheduled Task Executable',
                [TrawlerRiskPriority]::Low,
                'Scheduled Tasks',
                "T1053: Scheduled Task/Job",
                $task
            )
            $State.WriteDetection($detection)
        }
    }
}

function Assert-TaskMatchesRegex {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ItemName,
        [Parameter()]
        [string]
        $ItemContent
    )

    $knownSIDs = @{
        'S-1-5-17' = 'IUSR'
        'S-1-5-18' = 'SYSTEM'
        'S-1-5-19' = 'LOCAL_SERVICE'
        'S-1-5-20' = 'NETWORK_SERVICE'
    }

    $TaskMatches = [PSCustomObject]@{
        Author    = [regex]::Matches($ItemContent, '<Author>(.*)<\/Author>')
        RunAs     = [regex]::Matches($ItemContent, '<Principal id="(.*?)">')
        Command   = [regex]::Matches($ItemContent, '<Command>(.*)<\/Command>')
        Arguments = [regex]::Matches($ItemContent, '<Arguments>(.*)<\/Arguments>')
        UserId    = [regex]::Matches($ItemContent, '<UserId>(.*)</UserId>')
    }

    if ($TaskMatches.Author.Count -gt 0) {
        $author = $TaskMatches.Author.Groups[1].Value
    }

    if ($TaskMatches.RunAs.Count -gt 0) {
        $runas = $TaskMatches.RunAs.Groups[1].Value
        if ($runas -eq "Author") {
            $runas = $author
        }
    }

    if ($TaskMatches.Command.Count -gt 0) {
        $execute = $TaskMatches.Command.Groups[1].Value
    }

    if ($TaskMatches.Arguments.Count -gt 0) {
        $arguments = $TaskMatches.Arguments.Groups[1].Value
    }

    if ($TaskMatches.UserId.Count -gt 0) {
        $userid = $TaskMatches.UserId.Groups[1].Value

        if ($userid -eq 'System') {
            $userid = 'SYSTEM'
        }
        elseif ($userid -match 'S-.*') {
            if ($knownSIDs.ContainsKey($userid)) {
                $userid = $knownSIDs[$userid]
            }
        }

        if (-not $runas) {
            $runas = $userid
        }
            
        if (-not $author) {
            $author = $userid
        }
    }

    $task = [PSCustomObject]@{
        TaskName  = $ItemName
        Execute   = $execute
        Arguments = $arguments
        Author    = $author
        RunAs     = $runas
        UserId    = $userid
    }

    return [PSCustomObject]@{
        IsMatch = $null -ne $task.Exexcute
        Task    = $task
    }
}