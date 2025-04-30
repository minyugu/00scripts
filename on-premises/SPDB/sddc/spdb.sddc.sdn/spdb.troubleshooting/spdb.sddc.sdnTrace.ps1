#################################
# Start and Stop SDN Trace
# ver 0.01 20240924 power by mygu
#
# Sample command
# 1. Start capture trace
# @PowerShell.exe -NoExit -File "%~dp0sdnTrace.ps1" -op "start" -ncVM "shpdb22-sdn" -sdnHostName "sdnhost1.sdn.lab,sdnhost2.sdn.lab"
# .\sdnTrace.ps1 -op "start" -ncVM "shpdb22-sdn" -sdnHosts @("sdnhost1.sdn.lab", "sdnhost2.sdn.lab")
#
# 2. Stop capture trace
# @PowerShell.exe -NoExit -File "%~dp0sdnTrace.ps1" -op "stop" -ncVM "shpdb22-sdn" -sdnHostName "sdnhost1.sdn.lab,sdnhost2.sdn.lab"
# .\sdnTrace.ps1 -op "stop" -ncVM "shpdb22-sdn" -sdnHosts @("sdnhost1.sdn.lab", "sdnhost2.sdn.lab")
#################################

param
(
    [Parameter(Mandatory=$true)]
    [String]$ncVM,

    [Parameter(Mandatory=$true)]
    [String[]]$sdnHosts,

    [Parameter(Mandatory=$true)]
    [String]$op
)

#$sdnHosts = $sdnHostName.split(',') 

Import-Module "$PSScriptRoot\AzsHci.Networking.Sdn\AzsHci.Networking.Sdn.psd1"
$infraInfo = Get-SdnInfraInfo -NcVMName $ncVM

switch ($op)
{
    "Start" { # start trace
        Write-Host "1. Starting SDN Mux Trace..."
        Start-SdnMuxTrace -MuxVMs $infraInfo.Mux
        Write-Host "2. Starting SDN Host Trace..."
        Start-SdnHostTrace -SdnHosts $sdnHosts -IncludeVfp
    }
    "Stop" { # stop trace
        Write-Host "1. Stopping SDN Mux Trace..."
        Stop-SdnMuxTrace -MuxVMs $infraInfo.Mux
        Write-Host "2. Stopping SDN Host Trace..."
        Stop-SdnHostTrace -SdnHosts $sdnHosts -IncludeVfp
        Write-Host "3. Starting SDN Log Collection..."
        Start-SdnLogCollection -NcVMName $ncVM -Role NC,MUX,HyperV -sdnHosts $sdnHosts
    }
}
Write-Host "have a nice day"