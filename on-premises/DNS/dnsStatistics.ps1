<#
 .EXAMPLE
   .\dnsStatistics.ps1 -ComputerName corp-dc-01.corp.omygu.com,noThisName.corp.omygu.com,sha-dc-01.sha.corp.omygu.com,sha-hv-01.sha.corp.omygu.com
 .EXAMPLE
   <collection without clear>
   .\dnsStatistics.ps1 -all -ExcludeADSite BIZ-CLOUD,BIZ-HDQ,BIZ-RXY,BIZ-ZL,BIZ-ZLHF,BIZ2-HDQ
 .EXAMPLE
   <for test>
   .\dnsStatistics.ps1 -ComputerName corp-dc-01.corp.omygu.com,noThisName.corp.omygu.com,sha-dc-01.sha.corp.omygu.com,sha-hv-01.sha.corp.omygu.com -clear -minutes 5
 .EXAMPLE
   .\dnsStatistics.ps1 -all -clear -minutes 30 -ExcludeADSite BIZ-CLOUD,BIZ-HDQ,BIZ-RXY,BIZ-ZL,BIZ-ZLHF,BIZ2-HDQ
#>

#########################################
## verion 0.55 powered by mg @ 11/14/2024
#########################################

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, ParameterSetName='DNS Server Name', Position=0)]
    [Parameter(Mandatory=$true, ParameterSetName='DNS Server Name with clear', Position=0)]
    [String[]]$ComputerName,

    [Parameter(Mandatory=$true, ParameterSetName='All DNS Server')]
    [Parameter(Mandatory=$true, ParameterSetName='All DNS Server with clear')]
    [Switch]$all,

    [Parameter(Mandatory=$true, ParameterSetName='DNS Server Name with clear')]
    [Parameter(Mandatory=$true, ParameterSetName='All DNS Server with clear')]
    [Switch]$clear,

    [Parameter(Mandatory=$true, ParameterSetName='DNS Server Name with clear')]
    [Parameter(Mandatory=$true, ParameterSetName='All DNS Server with clear')]
    [Int]$minutes,

    [Parameter(Mandatory=$false, ParameterSetName='All DNS Server')]
    [Parameter(Mandatory=$false, ParameterSetName='All DNS Server with clear')]
    [String[]]$ExcludeADSite
)

$date = Get-Date

# log file path
$DnsClearResultsLog = "$PSScriptRoot\DnsClearResults_$($date.ToString('yyyyMMddhhmmss')).Log"
# statistics csv file path
$DnsStatisticCsv = "$PSScriptRoot\DnsStatistics_$($date.ToString('yyyyMMddhhmmss')).csv"

# Main
$info = "Start... # $(Get-Date)`n"
Write-Host $info -ForegroundColor Green; $output += $info
# region get dc
if ($all)
{
    $info = "[Starting] get AD DC name. $(Get-Date)`n"
    Write-Host $info -ForegroundColor Green; $output += $info
    $ComputerName = ( (Get-ADForest).Domains | ForEach-Object -Process { Get-ADDomainController -Filter * -Server $_ } | Where-Object {$_.Site -notin $ExcludeADSite} ).HostName
    $info = "[Completed] get AD DC name. $(Get-Date)`n"
    Write-Host $info -ForegroundColor Green; $output += $info
}
#endregion

#region clear DNS Server Statistics
if ($clear)
{
    Write-Host "To collect DNS Server statistics over a period of time, the DNS Server need to be clear." -ForegroundColor Yellow
    Write-Host "Press [Y] Yes, I confirm to clear statistics on ALL DNS SERVER."
    Write-Host "Press [N] No, I don't want to confirm to clear statistics.`n"

    $comfirmToClear = Read-Host -Prompt "Do you want to clear statistics on ALL DNS SERVER"

    if ($comfirmToClear -eq 'Y' -or $comfirmToClear -eq 'Yes' )
    {
        $info = "`n[Starting] clear Statistics. $(Get-Date)`n"
        Write-Host $info -ForegroundColor Green ; $output += $info

        $errorCountClear = $error.Count #get error count
        $DnsClearResults = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Try
            {
                Clear-DnsServerStatistics -Force | Out-Null
                return (
                           [PSCustomObject]@{
                           Status = "Succeed"
                           Info = ""
                           }
                       )
            }
            catch
            {
                return (
                           [PSCustomObject]@{
                           Status = "Failed"
                           Info = $_.toString()
                           }
                       )
            }
        } -ErrorAction SilentlyContinue

        # handling $DnsClearResults to Array
        if ($DnsClearResults -eq $null)
        {
            $DnsClearResults = @()
        }
        elseif ($DnsClearResults -isnot [Array])
        {
            $DnsClearResults = @($DnsClearResults)
        }

#region add invoke-command error to DnsClearResultss
        if( ($error.Count-$errorCountClear) -gt 0 )
        {
            $error[0..($error.Count-$errorCountClear-1)] | ForEach-Object -Process {
                if ($_.CategoryInfo.TargetName -in $DnsClearResults.PSComputerName)
                {
                    foreach ($dnsRes in $DnsClearResults)
                    {
                        if ($dnsRes.PSComputerName -eq $_.CategoryInfo.TargetName)
                        {
                            $dnsRes.Info  += ";;$($_.ToString())"
                            break
                        }
                    }
                }
                else
                {            
                    $DnsClearResults += [PSCustomObject]@{
                        Status = 'Failed'
                        Info = $_.ToString()
                        PSComputerName = $_.CategoryInfo.TargetName
                        PSShowComputerName = ''
                        RunspaceId = ''
                    }
    
                }
    
            }
        }
        $DnsClearResults | ft PSComputerName,Status,Info
        $DnsClearResults | ft PSComputerName,Status,Info | Out-File -FilePath $DnsClearResultsLog -Encoding utf8 -Force -Width 2000
        
        $info = "check clear dns statistic log file: `"$DnsClearResultsLog`""
        Write-Host $info -ForegroundColor Yellow ; $output += $info

        $info = "[Completed] clear Statistics. $(Get-Date)`n"
        Write-Host $info -ForegroundColor Green ; $output += $info
#endregion
        
        # waiting for start collection
        $sleepSec = 60
        $totalRemSec = $minutes*60
        do
        {
            Write-Host "$($totalRemSec / 60) minutes... the collection of DNS Server statistics will be started"
            Start-Sleep -Seconds $sleepSec
            $totalRemSec -= $sleepSec
        }
        until ($totalRemSec -le 0)
    }
}
#endregion

#region get dns server statistics from remote
$info = "`n[Starting] get Statistics. $(Get-Date)`n"
Write-Host $info -ForegroundColor Green ; $output += $info

$errorCount = $error.Count #get error count
$DnsStatistics = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    Try
    {
        $DnsStatistics = Get-DnsServerStatistics -ErrorAction Stop | Select-Object `
            @{ Name = 'ServerStartTime'; Expression = {$_.Timestatistics.ServerStartTime.ToString()} }, `
            @{ Name = 'LastClearTime'; Expression = {$_.Timestatistics.LastClearTime.ToString()} }, `
            @{ Name = 'RunStatisticsTime'; Expression = {(Get-Date).ToString()} }, `
            @{ Name = 'TimeElapsedSinceLastClearedStatistics'; Expression = {$_.Timestatistics.TimeElapsedSinceLastClearedStatistics.ToString()} }, `
            @{ Name = 'TotalQueries'; Expression = {$_.Query2Statistics.TotalQueries.ToString()} }, `
            @{ Name = 'TypeA'; Expression = {$_.Query2Statistics.TypeA.ToString()} }, `
            @{ Name = 'TypeSoa'; Expression = {$_.Query2Statistics.TypeSoa.ToString()} }, `
            @{ Name = 'TypeSrv'; Expression = {$_.Query2Statistics.TypeSrv.ToString()} }, `
            @{ Name = 'UdpQueries'; Expression = {$_.QueryStatistics.UdpQueries.ToString()} }, `
            @{ Name = 'UdpResponses'; Expression = {$_.QueryStatistics.UdpResponses.ToString()} }, `
            @{ Name = 'UdpQueriesSent'; Expression = {$_.QueryStatistics.UdpQueriesSent.ToString()} }, `
            @{ Name = 'UdpResponsesReceived'; Expression = {$_.QueryStatistics.UdpResponsesReceived.ToString()} }, `
            @{ Name = 'NotAuthoritative'; Expression = {$_.ErrorStatistics.NotAuthoritative.ToString()} }, `
            @{ Name = 'TcpQueries'; Expression = {$_.QueryStatistics.TcpQueries.ToString()} }, `
            @{ Name = 'TcpResponses'; Expression = {$_.QueryStatistics.TcpResponses.ToString()} }, `
            @{ Name = 'TcpClientConnections'; Expression = {$_.QueryStatistics.TcpClientConnections.ToString()} }, `
            @{ Name = 'Err_NxDomain'; Expression = {$_.ErrorStatistics.NxDomain.ToString()} }, `
            @{ Name = 'Err_Refused'; Expression = {$_.ErrorStatistics.Refused.ToString()} }, `
            @{ Name = 'Err_ServFail'; Expression = {$_.ErrorStatistics.ServFail.ToString()} }, `
            @{ Name = 'ErrorInfo'; Expression = {''} }
    }
    catch
    {
        $DnsStatistics += [PSCustomObject]@{
                ServerStartTime = ''
                LastClearTime = ''
                RunStatisticsTime = ''
                TimeElapsedSinceLastClearedStatistics = ''
                TotalQueries = ''
                TypeA = ''
                TypeSoa = ''
                TypeSrv = ''
                UdpQueries = ''
                UdpResponses = ''
                UdpQueriesSent = ''
                UdpResponsesReceived = ''
                NotAuthoritative = ''
                TcpQueries = ''
                TcpResponses = ''
                TcpClientConnections = ''
                Err_NxDomain = ''
                Err_Refused = ''
                Err_ServFail = ''
                ErrorInfo = $_.ToString()
        }
    }

    return $DnsStatistics
} -ErrorAction SilentlyContinue 

# handling $DnsClearResults to Array
if ($DnsStatistics -eq $null)
{
    $DnsStatistics = @()
}
elseif ($DnsStatistics -isnot [Array])
{
    $DnsStatistics = @($DnsStatistics)
}

$info = "[Completed] get Statistics. $(Get-Date)`n"
Write-Host $info -ForegroundColor Green ; $output += $info
#endregion

#region add invoke-command error to DnsStatistics 
$info = "`n[Starting] check invoke error. $(Get-Date)`n"
Write-Host $info -ForegroundColor Green ; $output += $info
if( ($error.Count-$errorCount) -gt 0 )
{
    $error[0..($error.Count-$errorCount-1)] | ForEach-Object -Process {
        if ($_.CategoryInfo.TargetName -in $DnsStatistics.PSComputerName)
        {
            foreach ($dnsStat in $DnsStatistics)
            {
                if ($dnsStat.PSComputerName -eq $_.CategoryInfo.TargetName)
                {
                    $dnsStat.ErrorInfo += ";;$($_.ToString())"
                    break
                }
            }
        }
        else
        {            
            $DnsStatistics += [PSCustomObject]@{
                ServerStartTime = ''
                LastClearTime = ''
                RunStatisticsTime = ''
                TimeElapsedSinceLastClearedStatistics = ''
                TotalQueries = ''
                TypeA = ''
                TypeSoa = ''
                TypeSrv = ''
                UdpQueries = ''
                UdpResponses = ''
                UdpQueriesSent = ''
                UdpResponsesReceived = ''
                NotAuthoritative = ''
                TcpQueries = ''
                TcpResponses = ''
                TcpClientConnections = ''
                Err_NxDomain = ''
                Err_Refused = ''
                Err_ServFail = ''
                ErrorInfo = $_.ToString()
                PSComputerName = $_.CategoryInfo.TargetName
                PSShowComputerName = ''
                RunspaceId = ''
            }
    
        }
    
    }
}
$info = "[Completed] check invoke error. $(Get-Date)`n"
Write-Host $info -ForegroundColor Green ; $output += $info
#endregion

#$DnsStatistics | ForEach-Object { $_.PSObject.Properties.Remove("PSShowComputerName") }
#$DnsStatistics | ForEach-Object { $_.PSObject.Properties.Remove("RunspaceId") }

$DnsStatistics | ft PSComputerName, TotalQueries, ErrorInfo
$DnsStatistics | Export-Csv -Path $DnsStatisticCsv -Force -Encoding UTF8 -NoTypeInformation

$info = "check Dns Statistic Csv file: `"$DnsStatisticCsv`""
Write-Host $info -ForegroundColor Yellow ; $output += $info

Write-Host "`n`njob done`n"

<#  
  Timestatistics
    TimeElapsedSinceLastClearedStatisticsBetweenRestart      //表示自上次清除统计数据以来到服务器重启之间的时间
    LastClearTime                                            //上次清除数据的时间
    ServerStartTime                                          //上次dns服务启动的时间
    TimeElapsedSinceLastClearedStatistics                    //自上次清除数据以来的总时间
    TimeElapsedSinceServerStartBetweenRestart                //服务器启动到重新启动之间的时间
    TimeElapsedSinceServerStart                              //自DNS服务器启动以来的总运行时间

  QueryStatistics
    TcpQueriesSent           //通过tcp发送的查询次数
    UdpResponsesReceived     //通过udp接收到的响应次数
    UdpQueries	             //通过udp接收到的查询次数
    UdpResponses             //通过udp发送的响应次数
    UdpQueriesSent           //通过udp发送的查询次数
    TcpResponsesReceived     //通过tcp接收到的响应次数
    TcpQueries               //通过tcp接收到的查询次数
    TcpResponses             //通过tcp发送的响应次数
    TcpClientConnections     //tcp客户端连接数

  Query2Statistics
    TypeAll         //查询所有记录的次数
    TKeyNego       //
    TypeOther      //
    TotalQueries   //总查询次数
    TypeMx         //
    TypeIxfr       //
    Notify         //
    Standard       //
    TypePtr        //
    TypeAxfr       //
    Update         //
    TypeSoa        //soa记录查询次数
    TypeNs         //
    TypeA          //A记录查询次数
    TypeSrv        //

  ErrorStatistics
    NoError            //
    NotAuthoritative   //非权威应答次数
    NxRRSet            //
    FormError          //
    YxDomain           //
    UnknownError       //
    NxDomain           //域名不存在的次数
    BadKey             //
    Max                //
    NotImpl            //
    NotZone            //
    BadSig             //
    BadTime            //
    Refused            //拒绝次数
    ServFail           //服务器故障次数，因故障，或者变更无法返回请求的次数
    YxRRSet            //
#>
