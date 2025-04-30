#################################
# Start and Stop SDN Trace
# ver 0.01 20240924 power by mygu
#
# Sample command
# 1. Start capture trace
# @PowerShell.exe -NoExit -File "%~dp0spdb.sddc.sdnTrace.ps1" -op "start" -ncVM "shpdb22-sdn" -sdnHostName "sdnhost1.sdn.lab,sdnhost2.sdn.lab" -OutputPath "c:\SDNTraceOutput"
# .\spdb.sddc.sdnTrace.ps1 -op "start" -ncVM "shpdb22-sdn" -sdnHosts @("sdnhost1.sdn.lab", "sdnhost2.sdn.lab") -OutputPath "c:\SDNTraceOutput"
#
# 2. Stop capture trace
# @PowerShell.exe -NoExit -File "%~dp0spdb.sddc.sdnTrace.ps1" -op "stop" -ncVM "shpdb22-sdn" -sdnHostName "sdnhost1.sdn.lab,sdnhost2.sdn.lab" -OutputPath "c:\SDNTraceOutput"
# .\spdb.sddc.sdnTrace.ps1 -op "stop" -ncVM "shpdb22-sdn" -sdnHosts @("sdnhost1.sdn.lab", "sdnhost2.sdn.lab") -OutputPath "c:\SDNTraceOutput"
#################################

param
(
    [Parameter(Mandatory=$true)]
    [String]$ncVM,

    [Parameter(Mandatory=$true)]
    [String[]]$sdnHosts,

    [Parameter(Mandatory=$true)]
    [String]$op,

    [Parameter(Mandatory=$true)]
    [String]$OutputPath
)

#$sdnHosts = $sdnHostName.split(',') 

Import-Module "$((Get-item -Path $PSScriptRoot).Parent.FullName)\AzsHci.Networking.Sdn\AzsHci.Networking.Sdn.psd1"
$infraInfo = Get-SdnInfraInfo -NcVMName $ncVM

switch ($op)
{
    "Start" { # start trace
        Write-Host "1. Starting SDN Mux Trace..." -ForegroundColor Green
        Start-SdnMuxTrace -MuxVMs $infraInfo.Mux
        Write-Host "2. Starting SDN Host Trace..." -ForegroundColor Green
        Start-SdnHostTrace -SdnHosts $sdnHosts -IncludeVfp
    }
    "Stop" { # stop trace
        Write-Host "1. Stopping SDN Mux Trace..." -ForegroundColor Yellow
        Stop-SdnMuxTrace -MuxVMs $infraInfo.Mux
        Write-Host "2. Stopping SDN Host Trace..." -ForegroundColor Yellow
        Stop-SdnHostTrace -SdnHosts $sdnHosts -IncludeVfp
        Write-Host "3. Starting SDN Log Collection..." -ForegroundColor Yellow

        $OutputPath += "\$(Get-Date -Format "yyyyMMddHHmmss")"
        New-Item $OutputPath -ItemType Directory -Force | Out-Null

        Start-SdnLogCollection -NcVMName $ncVM -Role NC,MUX,HyperV -sdnHosts $sdnHosts -OutputPath $OutputPath
    }
}
Write-Host "have a nice day"