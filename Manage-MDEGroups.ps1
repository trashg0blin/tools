import System.Collections.Generic

Import-Module Microsoft.Graph
Connect-AzureAD
Connect-Graph


function Create-DeviceTags(){
    Connect-MgGraph -Scopes "Machine.ReadWrite.All","Machine.ReadWrite"
    
}

function New-MDEManagementGroup(){
    $Country = 
    $DisplayName = "mde-$country-mgmt"
    $Description = "MDE Device Management group for $Country"
    New-AzureADGroup -Description $Description -DisplayName $DisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName 
}

function New-AzureAdDeviceGroup(){
    $Country = 
    $DisplayName = "$country-Devices"
    $Description = "Device Management group for $Country"
    $MembershipRule = "(device.displayName -contains '$Country')"
    New-AzureADMSGroup -Description $Description -DisplayName $DisplayName -MailEnabled $false -SecurityEnabled $true `
        -MailNickname $DisplayName -GroupTypes "DynamicMembership" -MembershipRule $MembershipRule -MembershipRuleProcessingState "On"
}

function New-IntuneTaggingPolicy(){
    $Country = "UK"
    $DisplayName = "MDE-$country-Tag"
    $Description = "Device tagging policy for $Country devices in MDE"

    #OMA Setting
    $OMAdata = @{}
    $OMAData.Add("@odata.type","#microsoft.graph.omaSettingString")
    $OMAdata.Add("displayName","$Country Device Tag")
    $OMAdata.Add("description","Tag device with $Country")
    $OMAdata.Add("OMAUri","./Device/Vendor/MSFT/WindowsAdvancedThreatProtection/DeviceTagging/Group")
    $OMAdata.Add("value","$Country")

    $AdditionalProperties = @{}
    $AdditionalProperties.Add("@odata.context",'https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceConfigurations/$entity')
    $AdditionalProperties.Add("@odata.type","#microsoft.graph.windows10CustomConfiguration")
    $AdditionalProperties.Add("omaSettings",$OMAdata)

    New-MgDeviceManagementDeviceConfiguration -DisplayName  $DisplayName -Description $Description -AdditionalProperties $AdditionalProperties 
}