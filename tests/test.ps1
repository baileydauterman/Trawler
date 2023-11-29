Pop-Location

Import-Module ..\src\Trawler.psd1 -Force
$state = [TrawlerState]::new()

$state.OutputPath = "..\detections.csv"
$state.SnapShotPath = "..\snapshot.csv"

$state.TryReadSnapShot()

$state