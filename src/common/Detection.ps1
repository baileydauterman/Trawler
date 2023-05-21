class Detection {
    [string]$Name
    [Risk]$Risk
    [string]$Source
    [string]$Technique
    [object]$Meta

    Detection(
        [string]$Name,
        [Risk]$Risk,
        [string]$Source,
        [string]$Technique,
        [object]$Meta
    ) {
        $this.Name = $Name
        $this.Risk = $Risk
        $this.Source = $Source
        $this.Technique = $Technique
        $this.Meta = $Meta
    }
}