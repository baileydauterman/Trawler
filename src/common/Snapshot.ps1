class Snapshot {
    [object] hidden $Data

    Snapshot([string]$path) {
        $this.Data = Import-Csv $path
    }

    [bool] CheckKey([string]$Source, [string]$Key, [string]$Value) {
        $checkList = $this.Data | Where-Object Source -eq $Source
	    return $checkList.Key -contains $Key -or $checkList.Value -contains $Value
    }

    [bool] CheckKeyValuePair([string]$Source, [string]$Key, [string]$Value) {
        $checkList = ($this.Data | Where-Object Source -eq $Source) | Where-Object Key -eq $Key | Select-Object -Unique

        if (!$checkList) {
            return $false
        }

        return $checkList.Key -eq $Key -and $checkList.Value -eq $Value
    }
}