function Get-TrawlerChildItem {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path,
        [Parameter()]
        [switch]
        $AsRegistry
    )

    if ($AsRegistry) {
        return Get-ChildItem -Path "Registry::$Path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    } else {
        return Get-ChildItem -Path $Path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    }
}

function Get-TrawlerItem {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path,
        [Parameter()]
        [switch]
        $AsRegistry
    )

    if ($AsRegistry) {
        return Get-Item -Path "Registry::$Path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    } else {
        return Get-Item -Path $Path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    }
}

function Get-TrawlerItemProperty {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path,
        [Parameter()]
        [switch]
        $AsRegistry
    )

    if ($AsRegistry) {
        return Get-ItemProperty -Path "Registry::$Path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    } else {
        return Get-ItemProperty -Path $Path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    }
}

function Test-TrawlerPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,
        [Parameter()]
        [switch]
        $AsRegistry
    )

    if ($AsRegistry) {
        return Test-Path -Path "Registry::$Path"
    } else {
        return Test-Path -Path $Path
    }
}