<#
 .SYNOPSIS
   Script that returns DIP's active state for specific VIP in SLB
 .DESCRIPTION
   Script that returns a DIP list that included active state.
   The DIP list returned is determined by VIP mapping in parameter
 .PARAMETER backendIps
   the DIP arrary of pararmeter $vipAddress 
 .EXAMPLE
   PS C:\> .\SlbVipDipActiveMappingAlert.ps1 -vipAddress 10.149.8.4 -vipPort 8103 -vipProtocol tcp -backendIps "172.20.30.160","172.20.30.161","192.168.1.1"
 .EXAMPLE
   PS C:\> .\SlbVipDipActiveMappingAlert.ps1 -vipAddress 10.149.8.4 -vipPort 8083 -vipProtocol udp -backendIps "172.20.30.23","172.20.30.138","172.20.30.139","192.168.1.1","172.20.30.144","172.20.30.145","172.20.30.11","172.20.30.155","172.20.30.156","172.20.30.157","172.20.30.158","172.20.30.123"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [String]$vipAddress,

    [Parameter(Mandatory=$true)]
    [String]$vipPort,

    [Parameter(Mandatory=$true)]
    [ValidateSet('Tcp','Udp','All')]
    [String]$vipProtocol,

    [Parameter(Mandatory=$true)]
    [String[]]$backendIps
)

$vipInfos = @()
$vipInfoFound = $false

$backendIpsActiveStates = @()

$statefulVipContents = Get-Content -Path "$($PSScriptRoot)/StatefulVip.txt"
foreach ($content in $statefulVipContents)
{
    if ($content -like "*$($vipProtocol ):$($vipAddress):$($vipPort):VipSourceAddress:*")
    {
        $vipInfos += $content
        $vipInfoFound = $true
    }
    elseif ($vipInfoFound)
    {
        if ($content -ne '')
        { 
            $vipInfos += $content
        }
        else
        {
            break 
        }
    }
}

if ($vipInfos.count -gt 0)
{
    Write-Host "Got active VIP DIP mapping...`n" -ForegroundColor Green
    Write-Host "$($vipInfos|out-string -Width 2000)"

    $backendIps | ForEach-Object -Process {
        $dipFound = $false
        foreach ($info in $vipInfos)
        {
            if ($info -like "*$($_)*")
            {
                $activeState = [PSCustomObject]@{
                    DIP = $_
                    State = 'Active'
                }
                $backendIpsActiveStates += $activeState
                $dipFound = $true
                break
            }
        }
        if (!$dipFound)
        {
            $activeState = [PSCustomObject]@{
                DIP = $_
                State = 'inactive'
            }
            $backendIpsActiveStates += $activeState
        }
    }
} else {
    Write-Error "Not found for active DIP mapping for VIP `"$($vipProtocol):$($vipAddress):$($vipPort)`"..." 
}

return ($backendIpsActiveStates | Sort-Object State,DIP)