class DetectionTracker {
    hidden [System.Collections.ArrayList]$Detections
    [bool] $Quiet
    [bool] $Writable
    [string] $Path

    DetectionTracker([bool]$q, [string]$p) {
        $this.Quiet = $q
        $this.Path = $p
        $this.Detections = [System.Collections.ArrayList]::new()
    }

    [void] AddDetection([Detection]$det) {
        $this.Detections.Add($det) | Out-Null

        if (-not($Quiet)) {
            Write-Host "[!] Detection: $($det.Name) - Risk: $($det.Risk)" -ForegroundColor (GetConsoleColor($det.Risk))
	        Write-Host "[%] $($det.Meta)" -ForegroundColor White
        }

        if ($this.Writable) {
            $det | Export-CSV $Path -Append -NoTypeInformation -Encoding UTF8
        }
    }

    [void] WriteMetrics() {
        Write-Host "[!] ### Detection Metadata ###" -ForeGroundColor White
        $this.WriteMessage("Total Detections: $($this.Detections.Count)")

        foreach ($str in ($this.Detections | Group-Object Risk | Select-Object Name, Count | Out-String).Split([System.Environment]::NewLine)) {
            if (-not ([System.String]::IsNullOrWhiteSpace($str))){
                $this.WriteMessage($str, $true)
            }
        }
    }

    [void] WriteMessage([string]$Message, [bool]$Tab=$false) {
        if ($Tab) {
            Write-Host "`t[+] $Message"
            return
        }

        Write-Host "[+] $Message"
    }

    [string] GetConsoleColor([Risk]$risk) {
        switch ($risk) {
            [Risk]::VeryLow  { return "Green" }
            [Risk]::Low      { return "Green" }
            [Risk]::Medium   { return "Yellow" }
            [Risk]::High     { return "Red" }
            [Risk]::VeryHigh { return "Magenta" }
            Default          { return "Yellow" }
        }
    }
}