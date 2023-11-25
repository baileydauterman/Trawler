@{

    # Script module or binary module file associated with this manifest.
    # RootModule = ''

    # Version number of this module.
    ModuleVersion    = '0.0.1'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID             = 'abed6242-683e-45be-8c86-3ddaf780d1a2'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules    = @(
        "./Trawler.psm1"
        "./helpers/data-grabbers.psm1"
        "./data/build-data.psm1"
        "./techniques/NoTechnique.psm1"
        "./techniques/T1037.psm1"
        "./techniques/T1053.psm1"
        "./techniques/T1055.psm1"
        "./techniques/T1059.psm1"
        "./techniques/T1071.psm1"
        "./techniques/T1098.psm1"
        "./techniques/T1112.psm1"
        "./techniques/T1136.psm1"
        "./techniques/T1137.psm1"
        "./techniques/T1197.psm1"
        "./techniques/T1219.psm1"
        "./techniques/T1484.psm1"
        "./techniques/T1505.psm1"
        "./techniques/T1543.psm1"
        "./techniques/T1546.psm1"
        "./techniques/T1547.psm1"
        "./techniques/T1553.psm1"
        "./techniques/T1574.psm1"
    )

    ScriptsToProcess = @(
        './TrawlerState.ps1'
    )
}

