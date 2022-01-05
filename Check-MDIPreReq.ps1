#This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
#THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING 
#BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a non-exclusive, 
#royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that 
#You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
#(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and 
#(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, 
#that arise or result from the use or distribution of the Sample Code.
#This posting is provided "AS IS" with no warranties, and confers no rights. 
#Use of included script samples are subject to the terms specified at https://www.microsoft.com/en-us/servicesagreement.
#

Param(
    [Parameter(Mandatory=$false)]
    [switch]$AutoFix,
    [Parameter(Mandatory=$false)]
    [switch]$SkipNpcapCheck,
    [Parameter(Mandatory=$false)]
    [switch]$SkipNpcapInstall,
    [Parameter(Mandatory=$false)]
    [string]$ProxyUrl="",
    [Parameter(Mandatory=$false)]
    [switch]$ProxyRequiresAuth=$false
) 

begin {
    function Get-CertStore{
        # Tested good 2020/04/25
        <#
            .SYNOPSIS
                Check the trusted root store for valid certs
            .DESCRIPTION
                This function check the trusted root certificate store to see if the DigiCert Baltimore Root and DigiCert Global Root G2 certificates are present
            .EXAMPLE
                Get-CertStore
            .Notes
                Author : Christopher Smith
                WebSite: https://github.com/ms-smithch
        #>
        [CmdletBinding()]
        [OutputType([bool])]
        [bool]$RootCertsPresent = $false
        [bool]$DigicertG2CertPresent = $false
        [bool]$BaltimoreCertPresent = $false
        write-output "Checking for root certs"
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

    function Set-WgetCommand {
        [CmdletBinding()]
        [OutputType([string])]
        Param(
            [string]$Uri,
            [string]$Outfile,
            [string]$ProxyUrl,
            [switch]$ProxyRequiresAuth

        )
        $wgetCmd = "Invoke-WebRequest -Uri $Uri -OutFile $Outfile"
        if ($ProxyUrl.length -gt 0) {
            # we need a proxy
            $wgetCmd +=" -Proxy "+$ProxyUrl
            # does it need auth?
            if ($ProxyRequiresAuth) {
                $proxyCreds = get-credential -Message "Enter credentials for Proxy $ProxyUrl"
                $wgetCmd += ' -ProxyCredential $proxyCreds' 
            }
        }
        return $wgetCmd
    }
}

process {
    #where are we
    $cd = (pwd).path
    # check for missing software
    write-output "Collecting install software inventory"
    $Apps = @()
    $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # 32 Bit
    $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"             # 64 Bit
    if (!($SkipNpcapCheck)) {
        #npcap 1
        # check version or install status of NPCAP
        # is it installed
        $npcapPresent = $false
        $npcapDesiredVersion = $false
        if ([bool]($Apps | ? { $_.publisher -eq "Nmap Project" })){
            $npcapPresent = $true
            # what version
            if (($Apps | ? { $_.publisher -eq "Nmap Project" }).VersionMajor -lt 1) {
                # it's old
                write-output "Npcap is installed but version is less than recommended version of 1.0"
            } else {
                $npcapDesiredVersion = $true
                write-output "Npcap is installed and version is greater than recommended version of 1.0"
            }
        } else {
            write-output "Npcap not found on system"
        }
        # do we need to take action for npcap?
        if (!($npcapDesiredVersion -and $npcapPresent)) {
            write-output "Action required for Npcap"
            if ($AutoFix) {
                write-output "Attempting to autofix Npcap status"
                if ($npcapPresent) {
                    $uninstallString = ($Apps | ? { $_.publisher -eq "Nmap Project" }).QuietUninstallString
                    write-output "Npcap present, attempting uninstall via $uninstallString"
                    iex "cmd /c $uninstallString"
                }
                    # if it's missing or version < 1 then you download
                    # ONLY IF AUTO FIX
                    # ONLY IF ALLOWED TO INSTALL
                    if (!($SkipNpcapInstall)){
                        # build wget command
                        if ($ProxyUrl.length -gt 0) {
                            # we need a proxy
                            # $wgetCmd +=" -Proxy "+$ProxyUrl
                            # does it need auth?
                            if ($ProxyRequiresAuth) {
                                $wgetCmd = Set-WgetCommand -Uri https://nmap.org/npcap/dist/npcap-1.00.exe -OutFile .\npcap-1.00.exe -Proxy $ProxyUrl -ProxyRequiresAuth
                            } else {
                                $wgetCmd = Set-WgetCommand -Uri https://nmap.org/npcap/dist/npcap-1.00.exe -OutFile .\npcap-1.00.exe -Proxy $ProxyUrl
                            }
                        } else {
                            $wgetCmd = Set-WgetCommand -Uri https://nmap.org/npcap/dist/npcap-1.00.exe -OutFile .\npcap-1.00.exe
                        }
                        # wget command built, execute download
                        try {
                            write-output "Attempting download of Npcap using command string $wgetCmd"
                            iex $wgetCmd
                            # install
                            $installString = ".\npcap-1.00.exe /loopback_support=no /winpcap_mode=yes"
                            write-output "Installing Npcap using install string $installString"
                            iex "cmd /c $installString"
                        }
                        catch {
                            write-error "FAILED to autofix Npcap"
                        }
                    }
            } else {
                if ($npcapPresent) {
                    $uninstallString = ($Apps | ? { $_.publisher -eq "Nmap Project" }).QuietUninstallString
                    write-output "Uninstall Npcap using this command in an elevated command prompt: $uninstallString"
                }
                write-output "Download recommended Npcap version from https://nmap.org/npcap/dist/npcap-1.00.exe"
                write-output "Install and unselect 'Loopback Support' and select 'WinPcap'"
            }
        }
    }
    # check for cpu session manager
    write-output "Checking for CPU custom scheduler"
    if ([bool](Get-ItemProperty -path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -name "EnableCpuQuota") 2> $null) {
        $regCheck = $false
        # check for old powershell
        if (($psversiontable).psversion.major -lt 5) {
            #old powershell check
            $regCheck = ((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System").EnableCpuQuota) -ne 0 2> $null
        }
        else {
            $regCheck = (Get-ItemPropertyValue -path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -name "EnableCpuQuota") -ne 0 2> $null
        }
        # if it's not 0 it needs to be fixed
        if ($regCheck) {
            if ($AutoFix) {
            write-output "Attempting to autofix EnableCpuQuota"
            try {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" -Name "EnableCpuQuota" -Value 0 -type DWord 2> $null
                write-output "SUCCESS to autofix EnableCpuQuota"
                write-output "REBOOT is required to finalize change"
            }
            catch {
                write-error "FAILED to remove registry entry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System"
            }
            } else {
                write-output "EnableCpuQuota is 1, to manually fix set registry entry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System\EnableCpuQuota to 0"
            }
        } else {
            write-output "Custom CPU scheduler value is correct"
        }
    } else {
        write-output "Custom CPU scheduler not configured"
    }

    #check perf counters status in registry
    $perfCountReg = @("PerfOs", "PerfProc", "PerfDisk", "PerfNet")
    write-output "Checking for disabled performance counters in the registry"
    $perfCountReg | %  {
        if ([bool](Get-ItemProperty -path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\$_\Performance -name "Disable Performance Counters") 2> $null) {
            if ($AutoFix) {
                write-output "Attempting to autofix disabled $_ counter"
                try {
                    Remove-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\$_\Performance -Name "Disable Performance Counters" 2> $null
                    write-output "SUCCESS to autofix disabled $_ counter"
                }
                catch {
                    write-error "FAILED to remove registry entry HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\$_\Performance\Disable Performance Counters"
                }
            } else {
                write-output "$_ is disabled, to manually fix remove registry entry HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\$_\Performance\Disable Performance Counters"
            }
        }
    }
    write-output "Finished checking for disabled performance counters in the registry"
    #check if perf counters need to be rebuilt
    #assume counters are in good shape
    #check them all and if ANY of them fail then we rebuild
    $perfCountExist = @{
        '[System.Diagnostics.PerformanceCounterCategory]::Exists("Processor Information")' = $true;
        '[System.Diagnostics.PerformanceCounterCategory]::CounterExists("% Processor Utility","Processor Information")' = $true;
        '[System.Diagnostics.PerformanceCounterCategory]::InstanceExists("_Total","Processor Information")' = $true;
        '[System.Diagnostics.PerformanceCounterCategory]::Exists("Network Interface")' = $true;
        '[System.Diagnostics.PerformanceCounterCategory]::Exists("Network Adapter")' = $true;
        '[System.Diagnostics.PerformanceCounterCategory]::CounterExists("Packets/sec","Network Adapter")' = $true;
    }
    #run the assessment
    write-output "Checking for missing or corrupted performance counters"
    $perfCountExist.Keys.Clone() | % { 
        $perfCountExist["$_"] = iex $_ 2> $null
    }
    #check for failures
    if (($perfCountExist.Values |? {$_ -eq $false}).count -gt 0 ) {
        write-output "Missing or corrupted counters found"
        if ($AutoFix) {
            write-output "Attempting to autofix missing or corrupted counters"
            cd c:\windows\system32 2> $null
            lodctr /R 2> $null
            cd c:\windows\sysWOW64 2> $null
            lodctr /R 2> $null
            WINMGMT.EXE /RESYNCPERF 2> $null
            cd $cd
        }
        else {
            write-output "To manually fix performance counters run the following commands from an elevated command prompt"
            write-output 'cd c:\windows\system32'
            write-output 'lodctr /R'
            write-output 'cd c:\windows\sysWOW64'
            write-output 'lodctr /R'
            write-output 'WINMGMT.EXE /RESYNCPERF'
        }
    }
    else {
        write-output "No missing or corrupted counters found"
    }
    #check for certificates
    if (!(Get-CertStore)) {
        write-output "Missing root certificates"
        # remediate
        if ($AutoFix) {
            write-output "Attempting auto fix"
            # download certs
            $certUrlArray = @("https://cacerts.digicert.com/DigiCertGlobalRootG2.crt", "https://cacerts.digicert.com/BaltimoreCyberTrustRoot.crt")
            $certUrlArray | % {
                # set file name becuase doing the split on function call causes extra new lines
                $f = ($_).split('/')[3]
                if ($ProxyUrl.length -gt 0) {
                # we need a proxy
                # $wgetCmd +=" -Proxy "+$ProxyUrl
                # does it need auth?
                    if ($ProxyRequiresAuth) {
                        $proxyCreds = get-credential -Message "Enter credentials for Proxy $ProxyUrl"
                        # $wgetCmd += ' -ProxyCredential $proxyCreds' 
                        $wgetCmd = Set-WgetCommand -Uri $_ -OutFile .\$f -Proxy $ProxyUrl -ProxyRequiresAuth
                    } else {
                        $wgetCmd = Set-WgetCommand -Uri $_ -OutFile .\$f -Proxy $ProxyUrl
                    }
                } else {
                    $wgetCmd = Set-WgetCommand -Uri $_ -OutFile .\$f
                }
                # write-output $wgetCmd
                try {
                    write-output "Downloading certificate $f" #using $wgetCmd"
                    iex $wgetCmd
                    Import-Certificate -FilePath .\$f  -CertStoreLocation 'Cert:\LocalMachine\Root' | out-null
                    write-output "Imported $f into ROOT store"
                }
                catch {
                    write-error "Failed to import certificate $f"
                }
            }

        } else {
            write-output "Missing root certificates. To remediate download https://cacerts.digicert.com/DigiCertGlobalRootG2.crt and https://cacerts.digicert.com/BaltimoreCyberTrustRoot.crt and install into the trusted root store"
        }
    } else {
        write-output "Required certificates present"
    }
    # check for disabled root cert updates
    # the script will autoremove the setting, but if it's GPO the GPO must be changed
    # also you'll need to update your cert store manually
    write-output "Checking for disabled root certificate updates"
    if (((Get-ItemProperty -path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates\AuthRoot -name "DisableRootAutoUpdate") 2> $null) -eq 1) {
        # the key is set
        write-output "System is configured to disable root cert updates"
        if ($AutoFix) {
            write-output "Attempting auto fix"
            try {
                Remove-ItemProperty -path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates\AuthRoot -name "DisableRootAutoUpdate" 2> $null
                write-output "Successfully removed DisableRootAutoUpdate value"
                write-output "Confirm no GPO is configured for this setting at Computer Configuration\System\Internet Communication Management\Internet Communication Settings\Turn off Automatic Root Certificates Update"
            }
            catch {
                write-error "Failed to remove DisableRootAutoUpdate value"
            }
        }
        else {
            write-output "To fix remove registry value HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates\AuthRoot\DisableRootAutoUpdate"
            write-output "Confirm no GPO is configured for this setting at Computer Configuration\System\Internet Communication Management\Internet Communication Settings\Turn off Automatic Root Certificates Update"
        }
    }
    else {
        write-output "Disabled root certificate updates not found"
    }
    # check for cipher quite modifications
    write-output "Checking for custom cipher suite modifications"
    if ([bool](Get-ItemProperty -path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -name "Functions") 2> $null) {
        write-output "Custom cipher suite found, checking order"
        if (($psversiontable).psversion.major -lt 5) {
            #old powershell check
            $regCheck = ((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002").Functions) 2> $null
        }
        else {
            $regCheck = (Get-ItemPropertyValue -path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -name "Functions") 2> $null
        }
        # is the appropriate cipher first in the list?
        if (($regCheck).split(',')[0] -ne 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384') {
            write-output "Incorrect order in cipher suites"
            if ($AutoFix) {
                # clone to arraylist
                [System.Collections.ArrayList]$ral = $regCheck.Split(',')
                # is the correct cipher in the list?
                if ($regCheck.Split(',').IndexOf('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384') -ne -1) {
                    # we need to re-order
                    # get index of, where is it?
                    $i = $regCheck.Split(',').IndexOf('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384')
                    # remove element
                    $ral.RemoveAt($i)
                }
                # add in at 0
                [System.Collections.ArrayList]$regNew = @()
                $regNew.Add('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384') | out-null
                $regNew.AddRange($ral)
                # write back to registry
                
                try {
                    write-output "Writing corrected cipher order to registry"
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value ([string](($regNew.ToArray()) -join ',')) -type String 2> $null
                    write-output "Successfully wrote corrected cipher order to registry"
                }
                catch {
                    write-error "Failed to write corrected cipher order to registry"
                }
                
            } else {
                write-output "Ensure that TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 is first in the list at HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions"
            } 
        } else {
            write-output "Correctly ordered custom cipher order found"
        }
    }
}