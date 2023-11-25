@{

    # Script module or binary module file associated with this manifest.
    # RootModule = ''

    # Version number of this module.
    ModuleVersion = '0.0.1'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID          = 'abed6242-683e-45be-8c86-3ddaf780d1a2'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        "./Trawler.psm1"
        "./helpers/data-grabbers.psm1"
        "./data/build-data.psm1"
        "./modules/AmsiProviders.psm1"
        "./modules/Applications.psm1"
        "./modules/AutoRunCommands.psm1"
        "./modules/BootVerificationProgram.psm1"
        "./modules/ComHijacks.psm1"
        "./modules/ContextMenu.psm1"
        "./modules/DiskCleanupHandlers.psm1"
        "./modules/DLLs.psm1"
        "./modules/FolderOpen.psm1"
        "./modules/GpoExtensions.psm1"
        "./modules/IFEO.psm1"
        "./modules/KnownHijacks.psm1"
        "./modules/LowILProcessIsolation.psm1"
        "./modules/Narrator.psm1"
        "./modules/Network.psm1"
        "./modules/NotepadPlusPlusPlugins.psm1"
        "./modules/Office.psm1"
        "./modules/RATs.psm1"
        "./modules/RDP.psm1"
        "./modules/ScheduledTasks.psm1"
        "./modules/ScmDacl.psm1"
        "./modules/Services.psm1"
        "./modules/SuspiciousFileLocations.psm1"
        "./modules/Windows.psm1"
        "./modules/WindowsLoadKey.psm1"
    )

    ScriptsToProcess = @(
        './TrawlerState.ps1'
    )
}

