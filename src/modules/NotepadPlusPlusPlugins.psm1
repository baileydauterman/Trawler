function Test-NotepadPlusPlusPlugins {
	# https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/
	# Supports Drive Retargeting
	Write-Message "Checking Notepad++ Plugins"
	$basepaths = @(
		"$env_homedrive\Program Files\Notepad++\plugins"
		"$env_homedrive\Program Files (x86)\Notepad++\plugins"
	)
	$allowlisted = @(
		".*\\Config\\nppPluginList\.dll"
		".*\\mimeTools\\mimeTools\.dll"
		".*\\NppConverter\\NppConverter\.dll"
		".*\\NppExport\\NppExport\.dll"
	)
	foreach ($basepath in $basepaths) {
		if (Test-Path $basepath) {
			$dlls = Get-ChildItem -Path $basepath -File -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue
			#Write-Host $dlls
			foreach ($item in $dlls) {
				$match = $false
				foreach ($allow_match in $allowlisted) {
					if ($item.FullName -match $allow_match) {
						$match = $true
					}
				}
				if ($match -eq $false) {
					$detection = [PSCustomObject]@{
						Name      = 'Non-Default Notepad++ Plugin DLL'
						Risk      = 'Medium'
						Source    = 'Notepad++'
						Technique = "T1546: Event Triggered Execution"
						Meta      = "File: " + $item.FullName + ", Created: " + $item.CreationTime + ", Last Modified: " + $item.LastWriteTime
					}
					Write-Detection $detection
				}
			}
		}
	}
}