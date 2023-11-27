function Test-T1553 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-TrustProviderDLL $State
	Test-SuspiciousCertificates $State
}
function Test-TrustProviderDLL {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Trust Provider")
	$path = "Registry::$($State.DriveTargets.Hklm)SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Dll' -and $_.Value -notin @("C:\Windows\System32\pwrship.dll", "C:\Windows\System32\WindowsPowerShell\v1.0\pwrshsip.dll")) {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Hijacking of Trust Provider'
					Risk      = [TrawlerRiskPriority]::VeryHigh
					Source    = 'Registry'
					Technique = "T1553: Subvert Trust Controls"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				$State.WriteDetection($detection)
			}
			if ($_.Name -eq 'FuncName' -and $_.Value -ne 'PsVerifyHash') {
				$detection = [PSCustomObject]@{
					Name      = 'Potential Hijacking of Trust Provider'
					Risk      = [TrawlerRiskPriority]::VeryHigh
					Source    = 'Registry'
					Technique = "T1553: Subvert Trust Controls"
					Meta      = "Key Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}, Entry Name: " + $_.Name + ", Entry Value: " + $_.Value
				}
				$State.WriteDetection($detection)
			}
		}
	}
}

function Test-SuspiciousCertificates {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Can maybe support drive retargeting
	if ($drivechange) {
		$State.WriteMessage("Skipping Certificate Analysis - No Drive Retargeting [yet]")
		return
	}
	# https://www.michev.info/blog/post/1435/windows-certificate-stores#:~:text=Under%20file%3A%5C%25APPDATA%25%5C,find%20all%20your%20personal%20certificates.
	$State.WriteMessage("Checking Certificates")
	$certs = Get-ChildItem -path cert:\ -Recurse | Select-Object *
	# PSPath,DnsNameList,SendAsTrustedIssuer,PolicyId,Archived,FriendlyName,IssuerName,NotAfter,NotBefore,HasPrivateKey,SerialNumber,SubjectName,Version,Issuer,Subject
	$wellknown_ca = @(
		"DigiCert.*",
		"GlobalSign.*",
		"Comodo.*",
		"VeriSign.*",
		"Microsoft Corporation.*",
		"Go Daddy.*"
		"SecureTrust.*"
		"Entrust.*"
		"Microsoft.*"
		"USERTrust RSA Certification Authority"
		"Blizzard.*"
		"Hellenic Academic and Research Institutions.*"
		"Starfield.*"
		"T-TeleSec GlobalRoot.*"
		"QuoVadis.*"
		"ISRG Root.*"
		"Baltimore CyberTrust.*"
		"Security Communication Root.*"
		"AAA Certificate Services.*"
		"thawte Primary Root.*"
		"SECOM Trust.*"
		"Certum Trusted Network.*"
		"SSL\.com Root Certification.*"
		"Amazon Root.*"
		'"VeriSign.*'
		"VeriSign Trust Network.*"
		"Microsoft Trust Network"
		"Thawte Timestamping CA"
		"GeoTrust Primary Certification Authority.*"
		"Certum CA"
		"XBL Client IPsec Issuing CA"
		"Network Solutions Certificate Authority"
		"D-TRUST Root Class 3 CA.*"
		"Hotspot 2.0 Trust Root CA.*"
	)
	$date = Get-Date
	foreach ($cert in $certs) {
		# Skip current object if it is a container of a cert rather than a certificate directly
		if ($cert.PSIsContainer) {
			continue
		}
		if ($cert.PSPath.Contains("\Root\") -or $cert.PSPath.Contains("\AuthRoot\") -or $cert.PSPath.Contains("\CertificateAuthority\")) {
			$trusted_cert = $true
		}
		else {
			continue
		}

		$cn_pattern = ".*CN=(.*?),.*"
		$cn_pattern_2 = "CN=(.*)"
		$ou_pattern = ".*O=(.*?),.*"
		$ou_pattern_2 = ".*O=(.*?)"

		$cn_match = [regex]::Matches($cert.Issuer, $cn_pattern).Groups.Captures.Value
		#Write-Host $cert.Issuer
		if ($cn_match) {
			#Write-Host $cn_match[1]
		}
		else {
			$cn_match = [regex]::Matches($cert.Issuer, $cn_pattern_2).Groups.Captures.Value
			if ($cn_match) {
				#Write-Host $cn_match[1]
			}
			else {
				$cn_match = [regex]::Matches($cert.Issuer, $ou_pattern).Groups.Captures.Value
				#Write-Host $cn_match[1]
				if ($cn_match -eq $null) {
					$cn_match = [regex]::Matches($cert.Issuer, $ou_pattern_2).Groups.Captures.Value
				}
			}
		}

		$signer = $cn_match[1]
		$diff = New-TimeSpan -Start $date -End $cert.NotAfter
		$cert_verification_status = Test-Certificate -Cert $cert.PSPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

		foreach ($ca in $wellknown_ca) {
			if ($signer -match $ca) {
				#Write-Host "Comparing:"+$signer+" to"+$ca
				$valid_signer = $true
				break
			}
			else {
				$valid_signer = $false
			}
		}

		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($cert.Issuer, $cert.Subject, 'Certificates'), $true)) {
			continue
		}


		# Valid Cert, Unknown Signer, Valid in Date, Contains Root/AuthRoot/CertificateAuthority
		if ($cert_verification_status -eq $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			$detection = [PSCustomObject]@{
				Name      = 'Valid Root or CA Certificate Issued by Non-Standard Authority'
				Risk      = [TrawlerRiskPriority]::Low
				Source    = 'Certificates'
				Technique = "T1553: Subvert Trust Controls: Install Root Certificate"
				Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
			}
			$State.WriteDetection($detection)
			#Write-Host $detection.Meta
		}
		if ($cert_verification_status -ne $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			$detection = [PSCustomObject]@{
				Name      = 'Invalid Root or CA Certificate Issued by Non-Standard Authority'
				Risk      = [TrawlerRiskPriority]::Low
				Source    = 'Certificates'
				Technique = "T1553: Subvert Trust Controls: Install Root Certificate"
				Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
			}
			$State.WriteDetection($detection)
			#Write-Host $detection.Meta
		}


		#$cert.SubjectName.Name
		# TODO - Maybe remove valid_signer from this later on if we care that much about 'valid' signer certs which failed validation
		if ($cert_verification_status -ne $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			# Invalid Certs that are still within valid range
			if ($cert.PSPath.Contains("\Root\")) {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Trusted Root Certificate Failed Validation'
					Risk      = [TrawlerRiskPriority]::Medium
					Source    = 'Certificates'
					Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
			elseif ($cert.PSPath.Contains("\AuthRoot\")) {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Third-Party Root Certificate Failed Validation'
					Risk      = [TrawlerRiskPriority]::Low
					Source    = 'Certificates'
					Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
			elseif ($cert.PSPath.Contains("\CertificateAuthority\")) {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Intermediary Certificate Failed Validation'
					Risk      = [TrawlerRiskPriority]::Low
					Source    = 'Certificates'
					Technique = "T1553.004: Subvert Trust Controls: Install Root Certificate"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
			else {
				$detection = [PSCustomObject]@{
					Name      = 'Installed Certificate Failed Validation'
					Risk      = [TrawlerRiskPriority]::VeryLow
					Source    = 'Certificates'
					Technique = "T1553: Subvert Trust Controls"
					Meta      = "Subject Name: " + $cert.SubjectName.Name + ", Friendly Name: " + $cert.FriendlyName + ", Issuer: " + $cert.Issuer + ", Subject: " + $cert.Subject + ", NotValidAfter: " + $cert.NotAfter + ", NotValidBefore: " + $cert.NotBefore
				}
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
		}
		elseif ($cert_verification_status -and $diff.Hours -ge 0) {
			# Validated Certs that are still valid
		}
	}
}