class StringConstants {
    static [string] $Logo = "
    __________  ___ _       ____    __________ 
   /_  __/ __ \/   | |     / / /   / ____/ __ \
    / / / /_/ / /| | | /| / / /   / __/ / /_/ /
   / / / _, _/ ___ | |/ |/ / /___/ /___/ _, _/ 
  /_/ /_/ |_/_/  |_|__/|__/_____/_____/_/ |_|  
      "
    static [string] $Title = "Trawler - Dredging Windows for Persistence"
    static [string] $Link = "https://github.com/joeavanzato/trawler"

    static [void] WriteHeader() {
        Write-Host $([StringConstants]::Logo) -ForegroundColor White
        Write-Host $([StringConstants]::Title) -ForegroundColor White
        Write-Host $([StringConstants]::Link) -ForegroundColor White
        Write-Host ""
    }
}