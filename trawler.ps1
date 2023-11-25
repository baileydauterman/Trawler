
# TODO - JSON Detection Output to easily encapsulate more details
# TODO - Non-Standard Service/Task running as/created by Local Administrator
# TODO - Browser Extension Analysis
# TODO - Temporary RID Hijacking
# TODO - ntshrui.dll - https://www.mandiant.com/resources/blog/malware-persistence-windows-registry
# TODO - Add file metadata for detected files (COM/DLL Hijacks, etc)
# TODO - Add more suspicious paths for running processes
# TODO - Iterate through HKEY_USERS when encountering HKEY_CURRENT_USER hive reference


# Snapshot acts as a custom allow-list for a specific gold-image or enterprise environment
# Run trawler once like '.\trawler.ps1 -snapshot' to generate 'snapshot.csv
# $message.key = Lookup component for allow-list hashtable
# $message.value = Lookup component for allow-list hashtable
# $message.source = Where are the K/V sourced from
# TODO - Consider implementing this as JSON instead of CSV for more detailed storage and to easier support in-line modification by other tools



function Assert-IsAllowed($allowmap, $key, $val, $det) {
	if ($allowmap.GetType().Name -eq "Hashtable") {
		if ($allowmap.ContainsKey($key)) {
			if ($allowmap[$key] -eq $val) {
				return $true
			}
			elseif ($allowmap[$key] -eq "" -and ($val -eq $null -or $val -eq "")) {
				return $true
			}
			else {
				Write-Detection $det
				return $false
			}
		}
	}
	elseif ($allowmap.GetType().Name -eq "ArrayList") {
		if ($allowmap.Contains($key) -or $allowmap.Contains($val)) {
			return $true
		}
		else {
			return $false
		}
	}
	else {
		Write-Warning "Invalid AllowMap Type Specified"
	}
}