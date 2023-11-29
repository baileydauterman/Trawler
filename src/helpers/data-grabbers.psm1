function Get-TrawlerItemData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,
        [Parameter(Mandatory)]
        [ValidateSet("Item", "ChildItem", "ItemProperty")]
        $ItemType,
        [Parameter()]
        [switch]
        $AsRegistry
    )

    if ($AsRegistry) {
        $Path = "Registry::$Path"
    }

    switch ($ItemType) {
        "Item" {
            return (Get-Item -Path $Path).PSObject.Properties
        }
        "ChildItem" {
            return (Get-ChildItem -Path $Path).PSObject.Properties
        }
        "ItemProperty" {
            return (Get-ItemProperty -Path $Path).PSObject.Properties
        }
    }
}

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
        return Get-ChildItem -Path "Registry::$Path" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    } else {
        return Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
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

function Get-TrawlerItemObjectProperties {
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
        return (Get-Item -Path "Registry::$Path").PSObject.Properties
    } else {
        return (Get-Item -Path $path).PSObject.Properties
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
        return Get-ItemProperty -Path $path -AsRegistry | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    } else {
        return Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
    }
}

function Get-TrawlerItemPropertyObjectProperties {
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
        return (Get-TrawlerItemProperty -Path $path -AsRegistry).PSObject.Properties
    } else {
        return (Get-TrawlerItemProperty -Path $path).PSObject.Properties
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