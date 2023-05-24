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

function Validate-Path {
    [[CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path
    )]
    try {
        [System.IO.File]::OpenWrite($Path).Close()
        return $true
    }
    catch {
        throw "Unable to write to path: $Path"
        return $false
    }
}