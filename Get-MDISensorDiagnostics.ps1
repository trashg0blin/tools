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

$global:Date = Get-Date -Format "yyyyMMddhhmm" -AsUTC
$global:FolderPath = "C:\Temp\SensorDiagnostics$date"

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
    try{
        $LogFolder = (Get-ChildItem -Path $InstallPath -Recurse | Where-Object {$_.Name -like "Logs"}).FullName
        Copy-Item $LogFolder -Recurse -Destination $FolderPath 
    }
    Catch{
        Write-Host "Error Fetching Sensor Logs."
    }
}

function Get-ServerEventLogs{
    $EventProviders = @("System","Security","Application")
    Foreach($Log in $EventProviders){
        try{
            $FileName = $FolderPath + $Hostname + "-" + $Log + "-" + $Date + ".evtx"
            Write-Host "Extracting the $log file now."
            wevtutil epl $Log $FileName
        }
        catch{
            Write-Host "Error fetching $log logs"
        }
    }
}


function Get-GroupPolicySettings{
    #TODO: Make this less janky
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ComputerName
    )
    [bool]$GPExportSuccesful = $false
    if (Get-GPResultantSetOfPolicy -ReportType xml -Computer "$ComputerName" -Path "$folderpath\GPResult-$ComputerName.xml")
    {
        $GPExportSuccesful = $true
    }
    return $GPExportSuccesful
}

function Export-Registry{
    #TODO: Make this less janky
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ComputerName
    )
    
    [bool]$RegExportSuccesful = $false
    if (Get-ChildItem HKCU:\ -recurse | Export-Clixml "$folderpath\$ComputerName.reg")
    {
        $RegExportSuccesful = $true
    }
    return $RegExportSuccesful
}

#TODO: Implement Remote tests.
# function Get-RemoteServerData{
#     [CmdletBinding()]
#     [OutputType([psobject])]
#     param (
#         [Parameter(Mandatory = $true,
#                    ValueFromPipelineByPropertyName = $true,
#                    Position = 0)]
#         [string]
#         $ComputerName
#     )
# }

# function Test-RemoteServerConnection{
#     [CmdletBinding()]
#     [OutputType([psobject])]
#     param (
#         [Parameter(Mandatory = $true,
#                    ValueFromPipelineByPropertyName = $true,
#                    Position = 0)]
#         [string]
#         $ComputerName
#     )
#     Test-WSMan -ComputerName $ComputerName
# }

function Test-SensorServiceConnectivity{
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $PortalURL
    )

    $NetTestResults = Test-NetConnection -Port 443 -ComputerName $PortalURL
    if ($NetTestResults.TcpTestSucceeded){
        return $true
    }
    else {
        return $false
    }
} 

# function Test-LdapBind{
#     ATALdapBindTester.exe 'contoso\_AtaSvc' 'Password' 'DC1.contoso.com' kerberos
# }

function Get-MDIAccount{
    <# 
    .SYNOPSIS 
        Gets information about the service account. 
    .DESCRIPTION
        This function will read the attributes of the Active Directory Service Account. 
    .EXAMPLE 
        Get-MDIServiceAccount -AccountName "Contoso\MDIAccount" -IsServiceAccount $True
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
        $AccountName
    )
    Get-ADServiceAccount $AccountName -Properties *
}

function Get-NetworkTrace{
    <# 
    .SYNOPSIS 
        Gathers a network Trace from the Domain Controller
    .DESCRIPTION
        This function will start a Network Capture on the specified Domain Controller. 
    .EXAMPLE 
        Get-NetworkTrace
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
        [bool]$NetworkTrace
    )
    if($NetworkTrace){
    New-NetEventSession -Name "MDISensorDebug" -LocalFilePath $FolderPath -CaptureMode SaveToFile
    Add-NetEventProvider -Name "Microsoft-Windows-TCPIP" -SessionName "MDISensorDebug"
    Start-NetEventSession -Name "MDISensorDebug"
    Start-Sleep -Seconds 300
    Stop-NetEventSession -Name "MDISensorDebug"
    }
    else{
        Write-Host "Network Capture not specified, skipping."
    }
}

function Test-NNRConnectivity{
    <# 
    .SYNOPSIS 
        Tests connection to other hosts to validate outbound NNR functionality
    .DESCRIPTION
        This function will attempt to establish a TCP handshake with another device on the network to validate NNR functionality. 
    .EXAMPLE 
        Test-NNRConnectivity -IPAddress 192.168.0.2
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

function Get-EventLogSDDL{
    <# 
    .SYNOPSIS 
        Get SDDLs for Application, Security, and System Event logs. 
    .DESCRIPTION
        This function gets the SDDLs for the Application, Security, and System Event logs and outputs them to a dictionary.
    .EXAMPLE 
        Compare-SDDL -SDDL "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)"
    .Notes 
        Author : Christopher Smith
        WebSite: https://github.com/ms-smithch 
    #> 
    $SDDLs = New-Object System.Collections.Generic.Dictionary"[string,string]"

    [string]$ApplicationLogSDDL = Get-WinEvent -ListLog Application | Select-Object -ExpandProperty SecurityDescriptor
    $SDDLs.Add("Application",$ApplicationLogSDDL)

    [string]$SecurityLogSDDL = Get-WinEvent -ListLog Security | Select-Object -ExpandProperty SecurityDescriptor
    $SDDLs.Add("Security",$SecurityLogSDDL)

    [string]$SystemLogSDDL = Get-WinEvent -ListLog System | Select-Object -ExpandProperty SecurityDescriptor
    $SDDLs.Add("System",$SystemLogSDDL)
    
    New-Object -Property $SDDLs -TypeName psobject 
}

function Compare-SDDL{
    <# 
        .SYNOPSIS 
            Compare the Presented SDDL with an expected entry
        .DESCRIPTION
            This function takes an input SDDL and references it against SDDL entries that will enable full functionality of an MDI sensor
        .EXAMPLE 
            Compare-SDDL -SDDL "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)"
        .Notes 
            Author : Christopher Smith
            WebSite: https://github.com/ms-smithch 
    #> 
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $SDDL
    )
    [bool]$MDIAccessPermitted = $false
    if (ConvertFrom-SddlString $SDDL){
        if ($SDDL -contains "(A;;0x1;;;S-1-5-80-818380073-2995186456-1411405591-3990468014-3617507088)" -or `
        $SDDL -contains "(A;;0x1;;;S-1-5-19)") {
            $MDIAccessPermitted = $true
        }
    }else{  
        Write-Host "Invalid SDDL Format"    
        return
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
    [CmdletBinding()]
    [OutputType([bool])]

    [bool]$RootCertsPresent = $false
    [bool]$DigicertG2CertPresent = $false
    [bool]$BaltimoreCertPresent = $false

    if (Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Thumbprint -eq "df3c24f9bfd666761b268073fe06d1cc8d4f82a4"}) {
        $DigicertG2CertPresent = $true
    }
    if (Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Thumbprint -eq "d4de20d05e66fc53fe1a50882c78db2852cae474" }) {
        $BaltimoreCertPresent = $true
    }
    if ($BaltimoreCertPresent -and $DigicertG2CertPresent) {
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
    [CmdletBinding()]
    [OutputType([string])]

    $proxies = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer

    if ($proxies){
        if ($proxies -ilike "*=*"){
            $proxies -replace "=","://" -split(';') | Select-Object -First 1
        }
        else{
            $ProxyAddress = "http://" + $proxies
        }
    }
   return $ProxyAddress  
}

function Get-MDISensorDiagnostics{
    $TestResults.ServerName = $env:COMPUTERNAME
    $TestResults.SensorInstallLocation = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName -like "*Azure*"} | Select-Object InstallLocation
    $TestResults.NNRResults = Test-NNRConnectivity
    
}
# TLS Versions somewhere along the line