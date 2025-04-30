<#
 .SYNOPSIS
   Script that returns DIP's active state for specific VIP in SLB
 .DESCRIPTION
   Script that returns a DIP list that included active state.
   The DIP list returned is determined by VIP mapping in parameter
 .PARAMETER backendIps
   the DIP arrary of pararmeter $vipAddress
 .PARAMETER Arguments
   the output redirect to SCOM when using the parameter
   the SCOM monitor Arguments, join all param with semicolon
 .EXAMPLE
   PS C:\> .\SlbVipDipActiveMappingAlert.ps1 -vipAddress 10.149.8.4 -vipPort 8103 -vipProtocol tcp -backendIps 172.20.30.160,172.20.30.16,192.168.1.1
 .EXAMPLE
   PS C:\> .\SlbVipDipActiveMappingAlert.ps1 -vipAddress 10.149.8.4 -vipPort 8083 -vipProtocol udp -backendIps 172.20.30.23,172.20.30.138,172.20.30.139,192.168.1.1,172.20.30.144,172.20.30.145,172.20.30.11,172.20.30.155,172.20.30.156,172.20.30.157,172.20.30.158,172.20.30.123
 .EXAMPLE
   PS C:\> .\SlbVipDipActiveMappingAlert.ps1 -vipAddress 10.145.138.154 -vipPort 1896 -vipProtocol tcp -backendIps 10.128.8.78,192.168.1.1
 .EXAMPLE
   PS C:\> .\SlbVipDipActiveMappingAlert.ps1 -vipAddress 10.145.137.160 -vipPort 0 -vipProtocol all -backendIps 172.10.10.28,192.168.1.1
 .EXAMPLE
   < Output to SCOM >
   < SCOM Monitor Config - UnHealthy Expression: ( Property[@Name="Health"] Equals UnHealthy )  >
   < SCOM Monitor Config - Healthy Expression: ( Property[@Name="Health"] Equals Healthy ) >
   < SCOM Alter Description >
   < $Data/Context/Property[@Name='ErrorList']$ >
   < $Data/Context/Property[@Name='ErrorInfoList']$ >

   PS C:\> .\SlbVipDipActiveMappingAlert.ps1 -Arguments "vipAddress=10.145.137.160;vipPort=0;vipProtocol=all;backendIps=172.10.10.28,192.168.1.1"
#>

###########################
## verion 1.0 powered by mg
###########################

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, ParameterSetName='Screen', Position=0)]
    [String]$vipAddress,

    [Parameter(Mandatory=$true, ParameterSetName='Screen')]
    [String]$vipPort,

    [Parameter(Mandatory=$true, ParameterSetName='Screen')]
    [ValidateSet('Tcp','Udp','All')]
    [String]$vipProtocol,

    [Parameter(Mandatory=$true, ParameterSetName='Screen')]
    [String[]]$backendIps,

    [Parameter(Mandatory=$false, ParameterSetName='SCOM', Position=0)]
    [String]$Arguments

)

$ErrorList=""
$ErrorInfoList=""
$HealthStatus = "Healthy"

$vipInfos = @()
$vipInfoFound = $false

$backendIpsActiveStates = @()

$PSNativeCommandUseErrorActionPreference = $ture


$comError = $null
$ArgumentsInvalid = $null

# convert scom arguments to var
if (![String]::IsNullOrEmpty($Arguments))
{
    # convert param Arguments from String to Hashtalbe
    $argsHash = ("$($Arguments.Replace(';',"`n"))" | ConvertFrom-StringData)
    # create var from Hashtable
    $argsHash.keys | ForEach-Object -Process { 
                                                 if ($_ -eq 'backendIps')
                                                 {
                                                    Set-Variable -Name backendIps -Value ($argsHash.backendIps).Split(',')
                                                 }
                                                 else
                                                 {
                                                     Set-Variable -Name $_ -Value $argsHash.$_ 
                                                 }
                                             }

    # check if param is complete and integrity
    if (
        [String]::IsNullOrEmpty($vipAddress) -or `
        [String]::IsNullOrEmpty($vipPort) -or `
        [String]::IsNullOrEmpty($vipProtocol) -or `
        [String]::IsNullOrEmpty($backendIps)
        )
    { $ArgumentsInvalid = $true }
}

# check if param is uncomplete
if ($ArgumentsInvalid)
{
    $HealthStatus = "UnHealthy"
    $ErrorList = "input arguments is incorrect"
    $ErrorList += "`n$Arguments"
}
else
{

    #$statefulVipContents = Get-Content -Path "$($PSScriptRoot)/StatefulVip.txt"
    try {
        # set error action to Stop for catching muxDriverControlConsole.exe excution error
    
        $errActPre = $ErrorActionPreference
        $ErrorActionPreference = 'stop'
        $statefulVipContents = (muxDriverControlConsole.exe /GetStatefulVip 2>&1)
        #$statefulVipContents, $cError = Invoke-Expression -Command "muxDriverControlConsole.exe /GetStatefulVipx 2>&1" -ErrorAction Stop -ErrorVariable $commandError

    } catch {
        $comError = $_
    
    } finally {
        $ErrorActionPreference = $errActPre
    }

    # chech exception of muxDriverControlConsole.exe excution
    if ($comError -ne $null)
    {
        $HealthStatus = "UnHealthy"
        $ErrorList = $comError.ToString()

    }
    # chech result of muxDriverControlConsole.exe excution
    elseif ($statefulVipContents -eq $null)
    {
        $HealthStatus = "UnHealthy"
        $ErrorList = "cumuxDriverControlConsole.exe /GetStatefulVip return is null"
    }
    else
    {
        # try to find vip($vipAddress) dip mapping in result of muxDriverControlConsole.exe excution
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

        # check if the mapping of vip($vipAddress)/dip is found
        if (!($vipInfos.count -gt 0))
        {
            $HealthStatus = "UnHealthy"
            $ErrorList = "Not found for active DIP mapping for VIP `"$($vipProtocol):$($vipAddress):$($vipPort)`"..."
        }
        else
        {
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
                        State = 'Inactive'
                    }
                    $backendIpsActiveStates += $activeState
                }
            }

            # check the DIP whether have 'Inactive' state
            if ('Inactive' -in $backendIpsActiveStates.State)
            {
                $HealthStatus = "UnHealthy"
                $ErrorList = "one or more DIP is inactive. VIP `"$($vipProtocol):$($vipAddress):$($vipPort)`"..."
            } else {
                $HealthStatus = "Healthy"
                $ErrorList = "All DIP is active. VIP `"$($vipProtocol):$($vipAddress):$($vipPort)`"..."
            }
        }
    }
}

###########################################################################
# check scom parma to determine output screen or SCOM 
if ([String]::IsNullOrEmpty($Arguments))
{
    Write-Host "Active VIP DIP mapping list...`n" -ForegroundColor Green
    Write-Host "$($vipInfos|out-string -Width 2000)"
    if ($HealthStatus -eq "Healthy")
    {
        Write-Host $HealthStatus -ForegroundColor Green
        Write-Host $ErrorList
    } else {
        Write-Host $HealthStatus -ForegroundColor Red
        Write-Host $ErrorList -ForegroundColor Yellow
    }
    return ($backendIpsActiveStates | Sort-Object State,DIP)
} else {
    $api = New-Object -ComObject "MOM.ScriptAPI"
    $PropertyBag = $api.CreatePropertyBag()
    $PropertyBag.AddValue("Health", $HealthStatus)
    $PropertyBag.AddValue("ErrorList", $ErrorList)

    $ErrorInfoList = "Active VIP DIP mapping list`n=============================================`n"
    $ErrorInfoList += "$($vipInfos|out-string -Width 2000)"
    $ErrorInfoList += "`nDIP States List`n============================================="
    $ErrorInfoList += ($backendIpsActiveStates | Sort-Object State,DIP |out-string -Width 2000)

    $PropertyBag.AddValue("ErrorInfoList", $ErrorInfoList)
    $PropertyBag
    #$api.Return($PropertyBag)
}