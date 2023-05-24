class ConsoleWriter {
    static [void] WriteMessage([LogLevel] $log, [string] $message) {
        switch ($log) {
            "None" {
                Write-Host "[%] $message"
            }
            "Info" { 
                Write-Host "[+] $message"
            }
            "Warning" {
                Write-Host "[!] $message" -ForegroundColor Yellow
            }
            "Error" {
                Write-Host "[!] $message" -ForegroundColor Red
            }
            Default {
                Write-Host $message
            }
        }
    }

    static [void] WriteInfo([string] $message) {
        [ConsoleWriter]::WriteMessage([LogLevel]::Info, $message)
    }

    static [void] WriteWarning([string] $message) {
        [ConsoleWriter]::WriteMessage([LogLevel]::Warning, $message)
    }

    static [void] WriteError([string] $message) {
        [ConsoleWriter]::WriteMessage([LogLevel]::Error, $message)
    }
}