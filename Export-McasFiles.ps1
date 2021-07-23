$APIKey = ""
$PolicyID = ""
$SkipCount = 0 
$TotalEntries = 0
do{
    try{
        $files = Get-MCASFile -PolicyId "$PolicyID" -Skip $SkipCount
    }
    catch{
        Start-Sleep -Seconds 30
        $files = Get-MCASFile -PolicyId "$PolicyID" -Skip $SkipCount -ErrorAction Stop
    }
    $TotalEntries += $files.Count
    $SkipCount += 100
}while ($TotalEntries%100 -eq 0)
