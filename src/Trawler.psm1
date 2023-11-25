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
		Start-Trawler -OutputPath "C:\detections.csv"

	.EXAMPLE
		Start-Trawler -OutputPath "C:\detections.csv" -ScanOptions ScheduledTasks, BITS
	
	.OUTPUTS
		None
	
	.NOTES
		None
	
	.INPUTS
		None
	
	.LINK
		https://github.com/joeavanzato/Trawler
#>
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

    # Initial state setup
    $trawlerState = [TrawlerState]::new();
    $trawlerState.Quiet = $Quiet
    $trawlerState.OutputPath = $OutputPath
    $trawlerState.CreateSnapShot = $CreateSnapShot
    $trawlerState.SnapShotPath = $SnapShotPath
    $trawlerState.TargetDrive = $TargetDrive
    $trawlerState.ScanOptions = $ScanOptions

    # Run the trawler program
    $trawlerState.Run()
}