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
		[object]
		$State
	)
	# Supports Drive Retargeting
	$State.WriteMessage("Checking Trust Provider")
	$path = "Registry::$($State.Drives.Hklm)SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}"
	if (Test-Path -Path $path) {
		$items = Get-TrawlerItemProperty -Path $path
		$items.PSObject.Properties | ForEach-Object {
			if ($_.Name -eq 'Dll' -and $_.Value -notin @("C:\Windows\System32\pwrship.dll", "C:\Windows\System32\WindowsPowerShell\v1.0\pwrshsip.dll")) {
				$detection = [TrawlerDetection]::new(
					'Potential Hijacking of Trust Provider',
					[TrawlerRiskPriority]::VeryHigh,
					'Registry',
					"T1553: Subvert Trust Controls",
					[PSCustomObject]@{
						KeyLocation = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}"
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				)
				$State.WriteDetection($detection)
			}
			if ($_.Name -eq 'FuncName' -and $_.Value -ne 'PsVerifyHash') {
				$detection = [TrawlerDetection]::new(
					'Potential Hijacking of Trust Provider',
					[TrawlerRiskPriority]::VeryHigh,
					'Registry',
					"T1553: Subvert Trust Controls",
					[PSCustomObject]@{
						KeyLocation = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}"
						EntryName   = $_.Name
						EntryValue  = $_.Value
					}
				)
				$State.WriteDetection($detection)
			}
		}
	}
}

function Test-SuspiciousCertificates {
	[CmdletBinding()]
	param (
		[Parameter()]
		[object]
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

		if ($State.IsExemptBySnapShot($cert.Issuer, $cert.Subject, 'Certificates')) {
			continue
		}


		# Valid Cert, Unknown Signer, Valid in Date, Contains Root/AuthRoot/CertificateAuthority
		if ($cert_verification_status -eq $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			$detection = [TrawlerDetection]::new(
				'Valid Root or CA Certificate Issued by Non-Standard Authority',
				[TrawlerRiskPriority]::Low,
				'Certificates',
				"T1553: Subvert Trust Controls: Install Root Certificate",
				[PSCustomObject]@{
					SubjectName    = $cert.SubjectName.Name
					FriendlyName   = $cert.FriendlyName
					Issuer         = $cert.Issuer
					Subject        = $cert.Subject
					NotValidAfter  = $cert.NotAfter
					NotValidBefore = $cert.NotBefore
				}
			)
			$State.WriteDetection($detection)
			#Write-Host $detection.Meta
		}
		if ($cert_verification_status -ne $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			$detection = [TrawlerDetection]::new(
				'Invalid Root or CA Certificate Issued by Non-Standard Authority',
				[TrawlerRiskPriority]::Low,
				'Certificates',
				"T1553: Subvert Trust Controls: Install Root Certificate",
				[PSCustomObject]@{
					SubjectName    = $cert.SubjectName.Name
					FriendlyName   = $cert.FriendlyName
					Issuer         = $cert.Issuer
					Subject        = $cert.Subject
					NotValidAfter  = $cert.NotAfter
					NotValidBefore = $cert.NotBefore
				}
			)
			$State.WriteDetection($detection)
			#Write-Host $detection.Meta
		}


		#$cert.SubjectName.Name
		# TODO - Maybe remove valid_signer from this later on if we care that much about 'valid' signer certs which failed validation
		if ($cert_verification_status -ne $true -and $valid_signer -eq $false -and $diff.Hours -ge 0) {
			# Invalid Certs that are still within valid range
			if ($cert.PSPath.Contains("\Root\")) {
				$detection = [TrawlerDetection]::new(
					'Installed Trusted Root Certificate Failed Validation',
					[TrawlerRiskPriority]::Medium,
					'Certificates',
					"T1553.004: Subvert Trust Controls: Install Root Certificate",
					[PSCustomObject]@{
						SubjectName    = $cert.SubjectName.Name
						FriendlyName   = $cert.FriendlyName
						Issuer         = $cert.Issuer
						Subject        = $cert.Subject
						NotValidAfter  = $cert.NotAfter
						NotValidBefore = $cert.NotBefore
					}
				)
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
			elseif ($cert.PSPath.Contains("\AuthRoot\")) {
				$detection = [TrawlerDetection]::new(
					'Installed Third-Party Root Certificate Failed Validation',
					[TrawlerRiskPriority]::Low,
					'Certificates',
					"T1553.004: Subvert Trust Controls: Install Root Certificate",
					[PSCustomObject]@{
						SubjectName    = $cert.SubjectName.Name
						FriendlyName   = $cert.FriendlyName
						Issuer         = $cert.Issuer
						Subject        = $cert.Subject
						NotValidAfter  = $cert.NotAfter
						NotValidBefore = $cert.NotBefore
					}
				)
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
			elseif ($cert.PSPath.Contains("\CertificateAuthority\")) {
				$detection = [TrawlerDetection]::new(
					'Installed Intermediary Certificate Failed Validation',
					[TrawlerRiskPriority]::Low,
					'Certificates',
					"T1553.004: Subvert Trust Controls: Install Root Certificate",
					[PSCustomObject]@{
						SubjectName    = $cert.SubjectName.Name
						FriendlyName   = $cert.FriendlyName
						Issuer         = $cert.Issuer
						Subject        = $cert.Subject
						NotValidAfter  = $cert.NotAfter
						NotValidBefore = $cert.NotBefore
					}
				)
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
			else {
				$detection = [TrawlerDetection]::new(
					'Installed Certificate Failed Validation',
					[TrawlerRiskPriority]::VeryLow,
					'Certificates',
					"T1553: Subvert Trust Controls",
					[PSCustomObject]@{
						SubjectName    = $cert.SubjectName.Name
						FriendlyName   = $cert.FriendlyName
						Issuer         = $cert.Issuer
						Subject        = $cert.Subject
						NotValidAfter  = $cert.NotAfter
						NotValidBefore = $cert.NotBefore
					}
				)
				$State.WriteDetection($detection)
				#Write-Host $detection.Meta
			}
		}
		elseif ($cert_verification_status -and $diff.Hours -ge 0) {
			# Validated Certs that are still valid
		}
	}
}