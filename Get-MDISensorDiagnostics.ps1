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

$TestResults = New-Object PSObject -Property @{
    Date                    = $date
    ServerName              = $Hostname
    ServiceAccount          = $user.name
    InstallDate             = $CreateDate
    Version                 = $Version
    CertsPresent            = $AreCertsPresent
    SensorInstallLocation   = $InstallPath
    IsRunning               = $ServiceStatus
    RegistryExportSuccess   = $RegistryExported
    EventLogSDDLs           = $SDDLs
    NNRResults              = $NNRTestResults
    SystemProxyPresent      = $IsProxied
    SystemProxyAddress      = $ProxyAddress 
}
           

function New-Archive {

}
function Get-SensorLogs{
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $InstallPath
    )
   
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
            } else 

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

function Get-EventLogDACL{
    <# 
    .SYNOPSIS 
        Get DACLs for Application, Security, and System Event logs. 
    .DESCRIPTION
        This function gets the DACLs for the Application, Security, and System Event logs and outputs them to a dictionary.
    .EXAMPLE 
        Compare-DACL -SDDL "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)"
    .Notes 
        Author : Christopher Smith
        WebSite: https://github.com/ms-smithch 
    #> 
    $DACLs = New-Object System.Collections.Generic.Dictionary"[string,string]"

    $NNRTestResults.Add("Application",(Get-WinEvent -ListLog Application | Select-Object -ExpandProperty SecurityDescriptor))
    $NNRTestResults.Add("Security",(Get-WinEvent -ListLog Security | Select-Object -ExpandProperty SecurityDescriptor))
    $NNRTestResults.Add("System",(Get-WinEvent -ListLog System | Select-Object -ExpandProperty SecurityDescriptor))
    
    New-Object -Property $DACLs -TypeName psobject 

}

function Compare-DACL{
    <# 
        .SYNOPSIS 
            Compare the Presented SDDL with an expected entry
        .DESCRIPTION
            This function takes an input SDDL and references it against SDDL entries that will enable full functionality of an MDI sensor
        .EXAMPLE 
            Compare-DACL -SDDL "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)"
        .Notes 
            Author : Christopher Smith
            WebSite: https://github.com/ms-smithch 
    #> 
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $SDDL
    )
    [bool]$MDIAccessPermitted = $false
    if ($SDDL -contains "(A;;0x1;;;S-1-5-80-818380073-2995186456-1411405591-3990468014-3617507088)" || `
        $SDDL -contains "(A;;0x1;;;S-1-5-19)") {
            $MDIAccessPermitted = $true
        }
    return $MDIAccessPermitted
}

function Get-CertStore{
        <# 
            .SYNOPSIS 
                Check the trusted root store for valid certs
            .DESCRIPTION
                This function check the trusted root certificate store to see if the DigiCert Baltimore Root and DigiCert Global Root G2 certificates are present
            .EXAMPLE 
                Get-InternetProxy
            .Notes 
                Author : Christopher Smith
                WebSite: https://github.com/ms-smithch 
    #> 

    [bool]$RootCertsPresent = $false
    [bool]$DigicertG2CertPresent = $false
    [bool]$BaltimoreCertPresent = $false

    if (Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Thumbprint -eq "df3c24f9bfd666761b268073fe06d1cc8d4f82a4"}) {
        $DigicertG2CertPresent = $true
    }
    if (Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Thumbprint -eq "D4DE20D05E66FC53FE1A50882C78DB2852CAE474"}) {
        $BaltimoreCertPresent = $true
    }
    if ($BaltimoreCertPresent && $DigicertG2CertPresent) {
        $RootCertsPresent = $true
    }
    return $RootCertsPresent       
}

function Get-ProxyConfig{
    <# 
            .SYNOPSIS 
                Determine the internet proxy address
            .DESCRIPTION
                This function allows you to determine the the internet proxy address used by your computer
            .EXAMPLE 
                Get-ProxyConfig
            .Notes 
                Author : Antoine DELRUE 
                WebSite: http://obilan.be 
    #> 

    $proxies = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer

    if ($proxies)
    {
        if ($proxies -ilike "*=*")
        {
            $proxies -replace "=","://" -split(';') | Select-Object -First 1
        }

        else
        {
            $ProxyAddress = "http://" + $proxies
        }
    }
   return $ProxyAddress  
}

function Main{
    $TestResults.ServerName = $env:COMPUTERNAME
    $TestResults.SensorInstallLocation = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Azure*"} | Select-Object InstallLocation
    $TestResults.NNRResults = Test-NNRConnectivity
    
}
# TLS Versions somewhere along the line