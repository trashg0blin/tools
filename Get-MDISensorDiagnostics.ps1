# Get-MDISensorDiagnostics
# Written by Chris Smith smithch@microsoft.com
#requires -version 2

<#
.Synopsis
Gathers Microsoft Defender for Identity Sensor diagnostic data for use in support cases.

.Description
The Telnet command tests the connectivity between two computers on a TCP Port. By running this command, you can determine if specific service is running on Server.

.Parameter <AllSensors>
This is a required parameter where you need to specify a computer name which can be localhost or a remote computer

.Parameter <Domain>
This is a required parameter where you need to specify a TCP port you want to test connection on.

.Parameter <DataPath>
This is an optional parameter where you can specify the folder of output file

.Example
Get-MIDSensorDiagnostics
Gathers local sensor diagnostic data

.Example
Get-MIDSensorDiagnostics -AllSensors -Domain "contoso.com"
Gathers all diagnostic data from all sensors within a forest

.Example
Get-MIDSensorDiagnostics -AllSensors -Domain "contoso.com"
Gathers all diagnostic data from all sensors within a given domain
#>
using namespace System.Collections.Generic

[CmdletBinding()]
param ()

$global:date = Get-Date -Format "yyyyMMddhhmm" -AsUTC
$global:folderPath = "C:\Temp\"

function New-Archive {

}
function Get-SensorLogs{
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Azure*"} | Select-Object InstallLocation
}

function Get-ServerEventLogs{
    #source https://gallery.technet.microsoft.com/scriptcenter/Retrieve-all-Events-from-5db61ec8
    Param(            
        [Parameter(Mandatory = $true)] 
        [Alias('BeginDate','BeginTime','StartDate')]  
        [ValidateScript({
                    (Get-Date $_)
        })]          
        [datetime]$StartTime,
        [Parameter(Mandatory = $true)] 
        [Alias('EndDate')]  
        [ValidateScript({
                    (Get-Date $_)
        })]          
        [datetime]$EndTime
    )  
    Write-Host "Gathering Event log data"
    $EventLogs = Get-WinEvent -ListLog * -ErrorVariable err -ea 0
    $err | ForEach-Object -Process {
        $warnmessage = $_.exception.message -replace '.*about the ', '' 
        Write-Warning -Message $warnmessage
    }

    $Count = $EventLogs.count

    $Events = $EventLogs |

    ForEach-Object -Process {
        $LogName = $_.logname
        $Index = [array]::IndexOf($EventLogs,$_)
        $Percentage = $Index / $Count
        $Message = "Retrieving events from Logs ($Index of $Count)"
     
        Write-Progress -Activity $Message -PercentComplete ($Percentage * 100) -CurrentOperation $LogName -Status 'Processing ...'
     
        Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ea 0
    } 

    if ($Events)
    {
        $EventsSorted = $Events  |
            Sort-Object -Property timecreated |
            Select-Object -Property timecreated, id, logname, leveldisplayname, message 
        
            test-path $ExportToCSVPath

                if (!$exists) {
                write-error "$ExportToCSVPath doesn't exist, re-run script ..."
                } else {
                $date = get-date
                $filename = "Events_$date`_$Computer.csv" -replace ':','_'
                $filename = $filename -replace '/','-'
                $EventsSorted | Export-csv ($ExportToCSVPath + '\' + $Filename)  -NoTypeInformation -Verbose
                } 
            } else {

       } # end if exporttocsv 

        
    }
    else 
    {
        Write-Warning -Message "`n`n`nNo events found between $StartTime and $EndTime"
    }

}

function Get-GroupPolicySettings{
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ComputerName
    )
    Get-GPResultantSetOfPolicy -ReportType xml -Computer "$ComputerName" -Path "$folderpath\GPResult-$ComputerName.xml"
}

function Export-Registry($domainController){

}

function Get-RemoteServerData($domainController){

}

function Test-RemoteServerConnection{

}

function Test-SensorServiceConnectivity{

} 

function Test-LdapBind{

}

function Get-NetworkTrace{
    New-NetEventSession -Name "MDISensorDebug" -LocalFilePath $folderPath

}

function Test-NNRConnectivity{
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $IPAddress
    )
    $NNRTestResults = New-Object System.Collections.Generic.Dictionary"[int,bool]"
    $Ports = 135,137,3389
    [bool]$Result = $false
    for ($i=0; $i -lt $ports.Length; $i++) {
        $Result = (Test-NetConnection -ComputerName $IPAddress -port $Ports[$i]).TcpTestSucceeded
        $NNRTestResults.Add($Ports[$i],$Result)
        $Result = $false #reset for next iteration
    }
    New-Object -Property $NNRTestResults -TypeName psobject 
}

function Get-CertStore{

}

function Get-ProxyConfig{
}
