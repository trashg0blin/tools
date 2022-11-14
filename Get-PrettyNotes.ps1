<#
    .SYNOPSIS
        Converts CSV to JSON and strips empty properties.
    .DESCRIPTION
        Script requires a CSV as input then will look through object properties to identify null values and strip them 
        from an object then outputs to the clipboard.
    .PARAMETER SourceCSV
        Identifies the source CSV as a file path. 
    .EXAMPLE 
        Get-PrettyNotes.ps1 -SourceCSV "C:\Users\contoso\some.csv"
#>
[CmdletBinding()]
param (
    [Parameter(mandatory=$true)]
    [String]
    $SourceCSV
)

$sourceEvents = Import-Csv $SourceCSV

$newSource = foreach ($i in $sourceEvents){
        $obj=New-Object PSObject
        $i | foreach{
            $props = $_.psobject.properties.name | Where {$i.$_}
            foreach($p in $props){
            $obj | Add-Member -memberType NoteProperty -Name $p -Value $i.$p
            }
        }
        $obj
    }

$Output = ConvertTo-Json $newSource
Set-Clipboard $Output
