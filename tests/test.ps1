Remove-Module Trawler -Force
Import-Module .\src\Trawler.psd1 -Force

function New-TestState {
    $state = [TrawlerState]::new()

    $state.OutputPath = "C:\Users\bailey\source\repos\Trawler\detections.csv"
    $state.SnapShotPath = "C:\Users\bailey\source\repos\Trawler\snapshot.csv"

    if (-not($state.TryReadSnapShot())) {
        throw "Unable to read snapshot"
    }

    $state.RetargetDrives()
    $state.ValidatePaths()

    return $state
}

$state = New-TestState