
function Test-AMSIProviders {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	# TODO - Add Snapshot Skipping
	# Supports Drive Retargeting
	$State.WriteMessage("Checking AMSI Providers")
	$allowedProviders = @(
		"{2781761E-28E0-4109-99FE-B9D127C57AFE}"
	)

	$path = "$regtarget_hklm\SOFTWARE\Microsoft\AMSI\Providers"
	if (Test-Path -Path $path) {
		foreach ($item in Get-TrawlerChildItem -Path $path -AsRegistry) {
			if ($item.PSChildName -in $allowedProviders) {
				continue
			}

			$new_path = "Registry::HKLM\SOFTWARE\Classes\CLSID\$($item.PSChildName)\InprocServer32"
			if (-not (Test-Path $new_path)) {
				continue
			}
			
			$State.WriteMessage("ASMI Providers checking: $new_path")
			
			$dll_data = Get-ItemProperty -Path $new_path
			foreach ($property in $dll_data.PSObject.Properties) {
				if ($property.Name -ne '(Default)') {
					continue
				}

				$State.WriteSnapShotMessage($property.Name, $property.Value, "AMSI")
				$State.WriteDetection([TrawlerDetection]::new(
					'Non-Standard AMSI Provider DLL',
					[TrawlerRiskPriority]::High,
					'Registry',
					"T1112: Modify Registry",
					[PSCustomObject]@{
						KeyLocation = $path
						EntryName = $_.Name
						EntryValue = $_.Value
					}
				))	
			}
		}
	}
}
