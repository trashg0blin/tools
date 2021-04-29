# Get-MDISensorDiagnostics
# Written by Chris Smith smithch@microsoft.com
#requires -version 2

<#
.Synopsis
Gathers Microsoft Defender for Identity Sensor diagnostic data for use in support cases.

.Example
Get-MIDSensorDiagnostics
Gathers local sensor diagnostic data

.Example
Get-MIDSensorDiagnostics -InstallPath "D:\Azure Advanced Threat Protection Sensor\"

.Example
Get-MIDSensorDiagnostics -NetworkTrace True
Gathers a network trace from the sensor

#>
using namespace System.Collections.Generic

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Enter the Install Path')]
    [string]
        $InstallPath = "C:\Program Files\Azure Advanced Threat Protection Sensor\",
    [Parameter(Mandatory = $false,
        HelpMessage = 'Set if a network capture is needed')]
    [bool]
        $NetworkTrace = $false
)

$global:Date = Get-Date -Format "yyyyMMddhhmm" # UTC would be a nice touch
$global:FolderPath = "C:\Temp\SensorDiagnostics$date\"

function main{
    $Outfile = $FolderPath + "TestResults.json" 
    $TestResults = New-Object PSObject -Property @{
        Date                    = $Date
        ServerName              = ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname
        ServiceAccount          = $user.name
        InstallDate             = $CreateDate
        Version                 = (Get-ChildItem -path $InstallPath `
            |  Sort-Object -Property LastWriteTime -Descending)[0].Name
        CertsPresent            = $AreCertsPresent
        SensorInstallLocation   = $InstallPath
        IsRunning               = $ServiceStatus
        GroupPolicyExportSuccess= $GPExportSuccesful
        RegistryExportSuccess   = $RegistryExported
        LogExportSuccess        = $LogExportResult
        EventLogExportSuccess   = $EventLogExportResult
        EventLogSDDLs           = $SDDLs
        CanAccessEventLogs      = $MDIAccessPermitted
        NNRResults              = $NNRTestResults            
        PortalURL               = $PortalURL
        CanConnectToService     = $NetTestResults
        SystemProxyPresent      = $false
        SystemProxyAddress      = $ProxyAddress
    }


    $TestResults.LogExportSuccess = Get-SensorLogs -InstallPath $InstallPath 
    $TestResults.EventLogExportSuccess = Get-ServerEventLogs
    $TestResults.GroupPolicyExportSuccess = Get-GroupPolicySettings 
    $TestResults.RegistryExportSuccess = Export-Registry
    $TestResults.CanConnectToService = Test-SensorServiceConnectivity
    Get-NetworkTrace $NetworkTrace
    $TestResults.NNRResults = Test-NNRConnectivity
    $TestResults.EventLogSDDLs = Get-EventLogSDDL
    $TestResults.CanAccessEventLogs = Compare-SDDL $TestResults.EventLogSDDLs.Security 
    $TestResults.CertsPresent = Get-CertStore 
    $TestResults.SystemProxyAddress = Get-ProxyConfig 
    if ($TestResults.SystemProxyAddress){$TestResults.SystemProxyPresent = $true} 
    ConvertTo-Json $TestResults | Out-File $Outfile

}
function New-Archive {

}
function Get-SensorLogs{
    # When testing in my own environment, I see issues where the InstallLocation of the RegKey fails to populate.
    # Using the folder name as a reference instead of RegKeys. 
    # Tested good 2020/04/25
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $InstallPath
    )
    [bool]$LogExportResult = $false
    try{
        Write-Host "Grabbing sensor logs."
        $LogFolder = (Get-ChildItem -Path $InstallPath -Recurse -ErrorAction Stop | Where-Object {$_.Name -like "Logs"}).FullName
        Copy-Item $LogFolder -Recurse -Destination $FolderPath -Force -ErrorAction Stop
        $LogExportResult = $True
        Write-Host "Sensor logs succesfully copied."
    }
    Catch{
        Write-Host "Error Fetching Sensor Logs."
        Write-Warning $Error[0]
        $LogExportResult = $False
    }
    return $LogExportResult
}

function Get-ServerEventLogs{
    #Tested good 2020/04/25
    $EventProviders = @("System","Security","Application")
    [bool]$EventLogExportResult = $false
    Foreach($Log in $EventProviders){
        try{
            $FileName = $FolderPath + $Log + "-" + $Date + ".evtx"
            Write-Host "Extracting the $log log file now."
            wevtutil epl $Log $FileName
            $EventLogExportResult = $true
        }
        catch{
            Write-Host "Error fetching $log logs"
            Write-Error $Error[0]
            $EventLogExportResult = $false
        }
    }
    return $EventLogExportResult
}

function Get-GroupPolicySettings{
    #Tested good 2020/04/25
    [bool]$GPExportSuccesful = $false
    $OutputFile = "$folderpath" + "GPResult.html"
    try {
        Write-Host "Grabbing Group Policy Settings."
        Get-GPResultantSetOfPolicy -ReportType html -Path $OutputFile
        $GPExportSuccesful = $true
    }
    catch {
        Write-Host "Unable to fetch output of GPResult"
        Write-Error $Error[0]
    }
    return $GPExportSuccesful
}

function Export-Registry{
    #Tested good 2020/04/25
    [bool]$Success = $false
    $FileName = $folderpath + "RegExport.reg"
    try {
        Get-ChildItem HKCU:\ -recurse | Export-Clixml $FileName -ErrorAction SilentlyContinue
        $Success = $true
    }
    catch {
        Write-Host "Error fetching registry"
        Write-Error $Error[0]
        $Success = $true
    }
    return $Success
}

function Test-SensorServiceConnectivity{
    # This can be written better, probably
    # But it works
    # Tested good 2020/04/25
    [bool]$NetTestResults = $false
    $FileName = $InstallPath + $TestResults.Version + "\SensorConfiguration.json"
    try {
        Write-Host "Testing connectivity to the sensor service"
        $SensorConfigFile = Get-Content $FileName -ErrorAction Stop | ConvertFrom-Json
        $PropToExpand = "WorkspaceApplicationSensorApiWebClientConfigurationServiceEndpoint"
        $TestResults.PortalURL = $SensorConfigFile.$PropToExpand.Address
        $NetTest = Test-NetConnection -Port 443 -ComputerName $TestResults.PortalURL
        if ($NetTest.TcpTestSucceeded){
            $NetTestResults = $true
        }
        else {
            $NetTestResults = $false
        }
    }
    catch {
        Write-Host "Failed to enumerate portal URL, will not test connection."
        Write-Error $Error[0]
    }
    return $NetTestResults
}
function Get-NetworkTrace{
    # Tested good 2020/04/25
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
    $OutputFile = $FolderPath + "NetCapture.etl"

    if($NetworkTrace){
        try{
            Write-Host "Attempting to capture network data."
            New-NetEventSession -Name "MDISensorDebug" -LocalFilePath $OutputFile -CaptureMode SaveToFile -ErrorAction SilentlyContinue
            Add-NetEventProvider -Name "Microsoft-Windows-TCPIP" -SessionName "MDISensorDebug" -ErrorAction SilentlyContinue
            Start-NetEventSession -Name "MDISensorDebug" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 300
            Stop-NetEventSession -Name "MDISensorDebug" -ErrorAction SilentlyContinue
        }
        catch{
            Write-Host "Network Capture failed."
            Write-Error $Error[0]
        }
    }
    else{
        Write-Host "Network Capture not specified, skipping."
    }
}

function Test-NNRConnectivity{
    # Tested good 2020/04/25
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
    Write-Host "Testing Network Name Resolution over ports 135,137,and 3389 on $IPaddress"
    for ($i=0; $i -lt $ports.Length; $i++) {
        $Result = (Test-NetConnection -ComputerName $IPAddress -port $Ports[$i]).TcpTestSucceeded
        $NNRTestResults.Add($Ports[$i],$Result)
        $Result = $false #reset for next iteration
    }
    New-Object -Property $NNRTestResults -TypeName psobject
}

function Get-EventLogSDDL{
    # Tested good 2020/04/25
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
    
    Write-Host "Grabbing SDDLs for event logs."

    [string]$ApplicationLogSDDL = Get-WinEvent -ListLog Application -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SecurityDescriptor
    $SDDLs.Add("Application",$ApplicationLogSDDL)

    [string]$SecurityLogSDDL = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SecurityDescriptor
    $SDDLs.Add("Security",$SecurityLogSDDL)

    [string]$SystemLogSDDL = Get-WinEvent -ListLog System -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SecurityDescriptor
    $SDDLs.Add("System",$SystemLogSDDL)

    New-Object -Property $SDDLs -TypeName psobject
}

function Compare-SDDL{
    # Tested good 2020/04/25
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
    $AtpSensorService = "*(A;;0x1;;;S-1-5-80-818380073-2995186456-1411405591-3990468014-3617507088)*" #probably shouldn't hard code this
    $NTNetworkService = "*(A;;0x1;;;S-1-5-19)*" #probably shouldn't hard code this
    [bool]$MDIAccessPermitted = $false
    Write-Host "Checking permissions to the event logs."
    if (ConvertFrom-SddlString $sddl){
        if ($SDDL -like $AtpSensorService -or $SDDL -like $NTNetworkService) {
            $MDIAccessPermitted = $true
        }
        else{
            return $MDIAccessPermitted
        }
    }
    else{
        Write-Host "Invalid SDDL Format"
        return
    }
    return $MDIAccessPermitted
}

function Get-CertStore{
    # Tested good 2020/04/25
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

    Write-Host "Checking for root certs"

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
    # Tested good 2020/04/25
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
    Write-Host "Grabbing current proxy config"

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

main #script entry point

#TODO: Implement LDAP Bind testing
# function Test-LdapBind{
#     ATALdapBindTester.exe 'contoso\_AtaSvc' 'Password' 'DC1.contoso.com' kerberos
# }

# Placeholder. I don't think this is entirely necessary. Would likely need more info for a service account 
#function Get-MDIAccount{
#     <#
#     .SYNOPSIS
#         Gets information about the service account.
#     .DESCRIPTION
#         This function will read the attributes of the Active Directory Service Account.
#     .EXAMPLE
#         Get-MDIServiceAccount -AccountName "Contoso\MDIAccount" -IsServiceAccount $True
#     .Notes
#         Author : Christopher Smith
#         WebSite: https://github.com/ms-smithch
#     #>
#     [CmdletBinding()]
#     [OutputType([psobject])]
#     param (
#         [Parameter(Mandatory = $true,
#                    ValueFromPipelineByPropertyName = $true,
#                    Position = 0)]
#         [string]
#         $AccountName
#     )
#     Get-ADServiceAccount $AccountName -Properties *
# }

# TLS Versions somewhere along the line