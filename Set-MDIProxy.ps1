# Chris Smith
# 
# THERE IS NO IMPLIED WARRANTY OR SUPPORT WITH THIS SCRIPT. USE AT YOUR OWN CAUTION.

$Files = Get-ChildItem 'C:\Program Files\Azure Advanced Threat Protection Sensor' -Recurse | where {$_.Name -like "SensorConfiguration.json"} | sort LastWriteTime -Descending 
$BackupFile = "C:\temp\" + $Files[0].Name + ".bak"
$NewProxy = "http://test.test.com:8080"

Write-Host "Grabbing file contents"
$Json = Get-content $Files[0].FullName -Raw | ConvertFrom-Json

Write-Host "Making Temp directory"
New-Item -ItemType Directory -Path "C:\Temp" -ErrorAction SilentlyContinue

Write-Host "Setting new address"
#Set new proxy address for the object
$Json.SensorProxyConfiguration.Url = $NewProxy

#Backup config
Write-Host "Backing up config"
Copy-Item $Files[0].FullName -Destination $BackupFile -Force

#Stop the sensor before we update the config
Write-Host "Stopping the sensor"
Stop-Service AATPSensorUpdater -Force

#Update the config and write it to file
Write-Host "Pushing new config"
ConvertTo-Json $Json | New-Item -ItemType file -Path $files[0].FullName -Force

#Start the service
Write-Host "Starting service"
Start-Service AATPSensorUpdater 

#Give it a second to think
Write-Host "Being Patient"
Start-Sleep -Seconds 60

#Backout changes. Checking the sensor instead of the updater.  
Write-Host "Checking to see if we broke anything"
if ((Get-Service AATPSensor).Status -ne "Running"){
Write-Host "Backing out of changes" 
Stop-Service AATPSensorUpdater -Force
Write-Host "Pushing original config" 
Move-Item $BackupFile -Destination $Files[0].FullName -Force
Start-Service AATPSensorUpdater -Force
}
