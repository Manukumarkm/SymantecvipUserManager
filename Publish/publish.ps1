$Modulepath = "$PSScriptroot\SymantecvipUsermanager"
Publish-Module -path $Modulepath -NuGetApiKey $env:APIKEY
