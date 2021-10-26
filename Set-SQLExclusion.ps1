#DISCLAIMER: NOT SUPPORTED BY MICROSOFT

$DriveLetter = "C"

$Data = "C:\Program Files\Microsoft Sql Server\"

$SQLDataFileQuery = "select * from sys.database_files"

function Get-SQLFolderLocations{
    $Install = Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\Setup"
    $Bin = $Install.SQLBinRoot
    $Data = $Install.SQLDataRoot 
    $ProgramDir = $Install.SqlProgramDir
}

$Extensions = {
    ".mdf",
    ".ldf",
    ".ndf",
    ".bak",
    ".trn",
    ".trc",
    ".sqlaudit",
    ".sql",
    ".xel",
    ".xem",
    ".mdmp",
    ".xtp*.c",
    ".xtp*.dll",#UNK if will work
    ".xtp*.obj",#UNK if will work
    ".xtp*.out",#UNK if will work
    ".xtp*.pdb",#UNK if will work
    ".xtp*.xml",#UNK if will work
    ".sch",
    ".idx",
    ".bcp",
    ".pre",
    ".cft",
    ".dri",
    ".trg",
    ".prc"
}
$Folders = {
    "$Data\MSSQL*\FTDATA",
    "$Data\MSSQL*\OLAP\Data",
    "$Data\MSSQL*\OLAP\Backup",
    "$Data\MSSQL*\OLAP\Log",
    "$Data\*\COM",
    "Q:\",
    "C:\Windows\Cluster",
    "$Data\MSSQL*.SERVER\MSSQL\RelpData"
    #NEED MSDTC DIRECTORY
    #NEEDS BACKUP LOCATION
}

$Processes = {
    "%ProgramFiles%\Microsoft SQL Server\<Instance_ID>.<Instance Name>\MSSQL\Binn\SQLServr.exe",
    "%ProgramFiles%\Microsoft SQL Server\<Instance_ID>.<Instance Name>\Reporting Services\ReportServer\Bin\ReportingServicesService.exe",
    "%ProgramFiles%\Microsoft SQL Server\<Instance_ID>.<Instance Name>\OLAP\Bin\MSMDSrv.exe",
    "%SystemRoot%\system32\msdtc.exe"
}

foreach ($i in $Extensions){
    Add-MpPrefence -ExlusionExtension $i
}
foreach ($i in $Folders){
    Add-MpPrefence -ExlusionFolder $i
}
foreach ($i in $Processes){
    Add-MpPrefence -ExlusionProcess $i
}
