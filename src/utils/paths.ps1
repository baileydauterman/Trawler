function Get-RegistryChildItem {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path
    )

    $Path = "Registry::$Path"
    
    if (!(Test-Path $Path)) {
        return;
    }

    Get-ChildItem -Path $Path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
}

function Get-ValidOutPath {
	param (
		[string]
		$Path
	)

	if (Test-Path -Path $Path -PathType Container)
	{
		Write-Host "The provided path is a folder, not a file. Please provide a file path." -Foregroundcolor "Yellow"
	}

	return $path
}