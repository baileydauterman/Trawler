function Test-T1053 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [TrawlerState]
        $State
    )

    Test-ScheduledTasks $State
}

function Test-ScheduledTasks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [TrawlerState]
        $State
    )

    begin {
        $State.WriteMessage("Checking Scheduled Tasks")
        $task_base_path = "$($State.TargetDrive)\Windows\System32\Tasks"
        $tasks = New-Object -TypeName "System.Collections.ArrayList"
        
    }

    process {
        if (-not (Test-Path $task_base_path)) {
            $State.WriteMessage("Could not find Scheduled Task Path: $task_base_path")
            return
        }

        foreach ($item in Get-ChildItem -Path $task_base_path -Recurse -ErrorAction SilentlyContinue) {
            $task = Assert-TaskMatchesRegex -Item $item

            if ($task.Matches) {
                $tasks.Add($task.Task) | Out-Null
            }
        }
    }
}

$author_pattern = '<Author>(?<Author>.*?)<\/Author>'
$runas_pattern = '<Principal id="(?<RunAs>.*?)">'
$execute_pattern = '<Command>(?<Execute>.*?)<\/Command>'
$argument_pattern = '<Arguments>(?<Arguments>.*?)<\/Arguments>'
$userid_pattern = '<UserId>(?<UserId>.*?)</UserId>'
$sid_lookup = @{
    'S-1-5-17' = 'IUSR'
    'S-1-5-18' = 'SYSTEM'
    'S-1-5-19' = 'LOCAL_SERVICE'
    'S-1-5-20' = 'NETWORK_SERVICE'
}

function Assert-TaskMatchesRegex {
    [CmdletBinding()]
    param (
        [Parameter()]
        $Item
    )

    $task_content = Get-Content $item.FullName -ErrorAction SilentlyContinue | Out-String
    if ($task_content) {
        continue
    }
    $task_content = [string]::join("", ($task_content.Split("`n")))
    #Write-Host $task_content[0]
    #$task_match = $regex_pattern.Match($task_content)

    $author_match = [regex]::Matches($task_content, $author_pattern)
    $runas_match = [regex]::Matches($task_content, $runas_pattern)
    $execute_match = [regex]::Matches($task_content, $execute_pattern)
    $arguments_match = [regex]::Matches($task_content, $argument_pattern)
    $userid_match = [regex]::Matches($task_content, $userid_pattern)


    if ($author_match[0]) {
        $author = "N/A"
    }
    else {
        $author = $author_match[0].Groups["Author"].Value
    }

    if ($runas_match[0]) {
        $runas = "N/A"
    }
    else {
        $runas = $runas_match[0].Groups["RunAs"].Value
        if ($runas -eq "Author") {
            $runas = $author
        }
    }

    if ($execute_match[0]) {
        $execute = "N/A"
    }
    else {
        $execute = $execute_match[0].Groups["Execute"].Value
    }
    if ($arguments_match[0]) {
        $arguments = "N/A"
    }
    else {
        $arguments = $arguments_match[0].Groups["Arguments"].Value
    }

    if ($userid_match[0]) {
        $userid = $author
    }
    else {
        $userid = $userid_match[0].Groups["UserId"].Value
        if ($userid -eq 'System') {
            $userid = 'SYSTEM'
        }
        elseif ($userid -match 'S-.*') {
            if ($sid_lookup.ContainsKey($userid)) {
                $userid = $sid_lookup[$userid]
            }
        }

        if ($runas -eq 'N/A') {
            $runas = $userid
        }
            
        if ($author -eq 'N/A') {
            $author = $userid
        }
    }

    $task = [PSCustomObject]@{
        TaskName  = $item.Name
        Execute   = $execute
        Arguments = $arguments
        Author    = $author
        RunAs     = $runas
        UserId    = $userid
    }

    return [PSCustomObject]@{
        Matches = $task.Exexcute -ne "N/A"
        Task    = $task
    }
}

function Test-ScheduledTasks {
    [CmdletBinding()]
    param (
        [Parameter()]
        [TrawlerState]
        $State
    )
    
    # Supports Dynamic Snapshotting for Executable Paths
    # Can possibly support drive-retargeting by parsing Task XML
    # Working on this with regex from Task Files
    # ^ Mostly working now
    # TODO - Add Argument Comparison Checks
    $State.WriteMessage("Checking Scheduled Tasks")

    $task_base_path = "$($State.Drives.HomeDrive)\Windows\System32\Tasks"
    $tasks = New-Object -TypeName "System.Collections.ArrayList"
    $author_pattern = '<Author>(?<Author>.*?)<\/Author>'
    $runas_pattern = '<Principal id="(?<RunAs>.*?)">'
    $execute_pattern = '<Command>(?<Execute>.*?)<\/Command>'
    $argument_pattern = '<Arguments>(?<Arguments>.*?)<\/Arguments>'
    $userid_pattern = '<UserId>(?<UserId>.*?)</UserId>'
    $sid_lookup = @{
        'S-1-5-17' = 'IUSR'
        'S-1-5-18' = 'SYSTEM'
        'S-1-5-19' = 'LOCAL_SERVICE'
        'S-1-5-20' = 'NETWORK_SERVICE'
    }

    if (-not (Test-Path -Path $task_base_path)) {
        $State.WriteMessage("Could not find Scheduled Task Path: $task_base_path")
        return
    }

    foreach ($item in Get-ChildItem -Path $task_base_path -Recurse -ErrorAction SilentlyContinue) {
        $task_content = Get-Content $item.FullName -ErrorAction SilentlyContinue | Out-String

        if ($task_content) {
            continue
        }

        $task_content = [string]::join("", ($task_content.Split("`n")))
        #Write-Host $task_content[0]
        #$task_match = $regex_pattern.Match($task_content)

        $author_match = [regex]::Matches($task_content, $author_pattern)
        $runas_match = [regex]::Matches($task_content, $runas_pattern)
        $execute_match = [regex]::Matches($task_content, $execute_pattern)
        $arguments_match = [regex]::Matches($task_content, $argument_pattern)
        $userid_match = [regex]::Matches($task_content, $userid_pattern)


        if ($author_match[0]) {
            $author = $author_match[0].Groups["Author"].Value
        }
        else {
            $author = "N/A"
        }

        if ($runas_match[0]) {
            $runas = $runas_match[0].Groups["RunAs"].Value
            if ($runas -eq "Author") {
                $runas = $author
            }
        }
        else {
            $runas = "N/A"
        }

        if ($execute_match[0]) {
            $execute = $execute_match[0].Groups["Execute"].Value
        }
        else {
            $execute = "N/A"
        }

        if ($arguments_match[0]) {
            $arguments = $arguments_match[0].Groups["Arguments"].Value
        }
        else {
            $arguments = "N/A"
        }

        if ($userid_match[0]) {
            $userid = $userid_match[0].Groups["UserId"].Value
            if ($userid -eq 'System') {
                $userid = 'SYSTEM'
            }
            elseif ($userid -match 'S-.*') {
                if ($sid_lookup.ContainsKey($userid)) {
                    $userid = $sid_lookup[$userid]
                }
            }
            if ($runas -eq 'N/A') {
                $runas = $userid
            }
            if ($author -eq 'N/A') {
                $author = $userid
            }
        }
        else {
            $userid = $author
        }

        $task = [PSCustomObject]@{
            TaskName  = $item.Name
            Execute   = $execute
            Arguments = $arguments
            Author    = $author
            RunAs     = $runas
            UserId    = $userid
        }
        if ($task.Execute -ne "N/A") {
            $tasks.Add($task) | Out-Null
        }
    }
    
    #$tasks = Get-ScheduledTask  | Select-Object -Property State,Actions,Author,Date,Description,Principal,SecurityDescriptor,Settings,TaskName,TaskPath,Triggers,URI, @{Name="RunAs";Expression={ $_.principal.userid }} -ExpandProperty Actions | Select-Object *
    $TaskDefaults = Build-ScheduledTaskDefaults -State $State

    foreach ($task in $tasks) {
        # Allowlist Logic
        if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($task.TaskName, $task.Execute, "Scheduled Tasks"))) {
            continue
        }

        # Detection - Non-Standard Tasks
        foreach ($i in $TaskDefaults.ExecutablePaths) {
            if ( $task.Execute -like $i) {
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
                ($task | Select-Object TaskName, Execute, Arguments, Author, RunAs)
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
                ($task | Select-Object TaskName, Execute, Arguments, Author, RunAs)
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
                ($task | Select-Object TaskName, Execute, Arguments, Author, RunAs)
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
                ($task | Select-Object TaskName, Execute, Arguments, Author, RunAs)
            )
            $State.WriteDetection($detection)
        }
        # Detection - User Created Tasks
        if ($task.Author) {
            if (($task.Author).Contains("\")) {
                if ((($task.Author.Split('\')).count - 1) -eq 1) {
                    if ($task.RunAs -eq "SYSTEM") {
                        # Current Task Executable Path is non-standard
                        $detection = [TrawlerDetection]::new(
                            'User-Created Task running as SYSTEM',
                            [TrawlerRiskPriority]::High,
                            'Scheduled Tasks',
                            "T1053: Scheduled Task/Job",
                            ($task | Select-Object TaskName, Execute, Arguments, Author, RunAs)
                        )
                        $State.WriteDetection($detection)
                        continue
                    }
                    # Single '\' in author most likely indicates it is a user-made task
                    $detection = [TrawlerDetection]::new(
                        'User Created Task',
                        [TrawlerRiskPriority]::Low,
                        'Scheduled Tasks',
                        "T1053: Scheduled Task/Job",
                        ($task | Select-Object TaskName, Execute, Arguments, Author, RunAs)
                    )
                    $State.WriteDetection($detection)
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
                ($task | Select-Object TaskName, Execute, Arguments, Author, RunAs)
            )
            $State.WriteDetection($detection)
        }
    }
}