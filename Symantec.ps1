$SymExclusions=Select-Xml -Path .\Sample.xml -XPath '//Exclusion'| Select-Object -ExpandProperty Node
foreach($i in $SymExclusions){
    switch ($i.Type) {
        FileName {Set-MpPreference -ExclusionPath "$i.value"}
        Extension {Set-MpPreference -ExclusionExtension "$i.value"}
        FolderPath {Set-MpPreference -ExclusionPath "$i.value"}
    }
}