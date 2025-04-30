##############################
# ADUpgradeAssessment.ps1
# verion 1.03
# mg
##############################
$logFile = "$($PSScriptRoot)\ADUpgradeAssessment.log"
#$logFile = "$([Environment]::GetFolderPath("Desktop"))\ADUpgradeAssessment.log"

$output = ""
$info = ""

# 1.Forest
$info = "1.Start get AD Forest info. # $(Get-Date)`n"
Write-Host $info; $output += $info

$output += (Get-ADForest | FT Name, RootDomain, Domains, ForestMode, Sites, SchemaMaster, DomainNamingMaster | Out-String -Width 2000)

# 2.Domain
$info = "`n2.Start get AD Domain info. # $(Get-Date)`n"
Write-Host $info; $output += $info
$output += ((Get-ADForest).Domains | Get-ADDomain | ft DNSRoot, NetBIOSName, Forest, ParentDomain, ChildDomains, DomainMode, PDCEmulator, RIDMaster, InfrastructureMaster | Out-String -Width 2000)

# 3.DC
$info = "`n3.Start get AD DC info. # $(Get-Date)`n"
Write-Host $info; $output += $info
$DCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ }

$info = ($DCs | ft -Property Name,Domain,Site,IPv4Address,OperatingSystem,OperatingSystemVersion,isreadonly,IsGlobalCatalog, `
                    @{ L="ComputerManufacturer"; E={(Get-WmiObject Win32_ComputerSystem).Manufacturer}}, @{ L="ComputerModel"; E={(Get-WmiObject Win32_ComputerSystem).model}} | Out-String)
Write-Host $info

$output += ($DCs | ft -Property Name,HostName,ComputerObjectDN,Domain,Forest,Site,IPv4Address,OperatingSystem,OperatingSystemVersion,isreadonly,IsGlobalCatalog, `
                        @{ L="ComputerManufacturer"; E={(Get-WmiObject Win32_ComputerSystem).Manufacturer}}, @{ L="ComputerModel"; E={(Get-WmiObject Win32_ComputerSystem).model}}, `
                        @{ L="OperationMasterRoles"; E={(($_.OperationMasterRoles) | foreach { $_.ToString()}) -join ', '} } | Out-String -Width 2000)
&pause


# 4.Site
$info = "`n4.Start get AD Site info. # $(Get-Date)`n"
Write-Host $info; $output += $info
$a = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", ((Get-ADForest).Name))
$output += ([System.DirectoryServices.ActiveDirectory.Forest]::GetForest($a).sites | ft Name,Domains,Subnets,Servers,AdjacentSites,SiteLinks,InterSiteTopologyGenerator,BridgeheadServers | Out-String -Width 2000)

# 5.replication
$info = "`n5.Start get AD Replication info. # $(Get-Date)`n`n"
Write-Host $info; $output += $info
$output += (&repadmin /showrepl * /csv | Out-String -Width 2000)

# 6.computer
$info = "`n6.Start get AD Compouter info. # $(Get-Date)`n"
Write-Host $info; $output += $info
$output += (Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | ft Name,Count | Out-String -Width 2000)

# 7.DC info
$info = "`n7.Start get DC info. # $(Get-Date)`n"
Write-Host $info; $output += $info

$DCsName = $DCs.HostName
$i = 0
foreach ($server in $DCsName)
{
    if(!([String]::IsNullOrEmpty($server)))
    {
        $i++
        $info = "`n7.$($i).Start get [$($server)] info. # $(Get-Date)==================================`n"
        Write-Host $info; $output += $info
        $server = $server.Trim()
        $output += Invoke-Command -ComputerName $server -ScriptBlock {
            param([Int]$i)

            $rmtOutput = ""
            $rmtInfo = ""

            # 1.IP
            $rmtInfo = "`n7.$($i).1.Start get IP Address info. #[$($env:COMPUTERNAME)] $(Get-Date)`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo            
            $rmtOutput += (&ipconfig /all | Out-String -Width 2000)

            # 2.Dcdiag
            $rmtInfo = "`n7.$($i).2.Start get DCDiag info. #[$($env:COMPUTERNAME)] $(Get-Date)`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo            
            $rmtOutput += (&Dcdiag /v | Out-String -Width 2000)

            # 3.Windows Time
            $rmtInfo = "`n7.$($i).3.Start get Windows Time info. #[$($env:COMPUTERNAME)] $(Get-Date)`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo            
            $rmtOutput += (&w32tm /query /status | Out-String -Width 2000)
            $rmtOutput += "`n"
            $rmtOutput += (&w32tm /query /Configuration | Out-String -Width 2000)

            # 4.Windows Feature
            $rmtInfo = "`n7.$($i).4.Start get Windows Feature info. #[$($env:COMPUTERNAME)] $(Get-Date)`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo            
            $rmtOutput += (Get-WindowsFeature | where {$_.InstallState -eq "Installed" } | Out-String -Width 2000)
            
            
            ### 5.DNS Server info
            ### DNS Server info
            $rmtInfo = "`n7.$($i).5.Start get DNS Server info. #[$($env:COMPUTERNAME)] $(Get-Date)`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo            
            
            # 5.1.DNS DnsServerZone
            $rmtInfo = "`n7.$($i).5.1.[DnsServerZone]`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo   
            $rmtOutput += ((Get-DnsServerZone | ft ZoneName, ZoneType,MasterServers, IsAutoCreated, IsDsIntegrated, ReplicationScope, IsReverseLookupZone, IsSigned, DynamicUpdate, `
                @{L="AgingEnabled";E={if($_.ZoneType -eq "Primary"){($_ | Get-DnsServerZoneAging).AgingEnabled}}}, `
                @{L="NoRefreshInterval";E={if($_.ZoneType -eq "Primary"){($_ | Get-DnsServerZoneAging).NoRefreshInterval}}}, `
                @{L="RefreshInterval";E={if($_.ZoneType -eq "Primary"){($_ | Get-DnsServerZoneAging).RefreshInterval}}}) | Out-String -Width 2000)
            
            # 5.2.DNS DnsServerScavenging
            $rmtInfo = "`n7.$($i).5.2.[DnsServerScavenging]`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo   
            $rmtOutput += (Get-DnsServerScavenging | Out-String -Width 2000)

            # 5.3.DNS DnsServerRecursion
            $rmtInfo = "`n7.$($i).5.3.[DnsServerRecursion]`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo   
            $rmtOutput += (Get-DnsServerRecursion | Out-String -Width 2000)

            # 5.4.DNS DnsServerForwarder
            $rmtInfo = "`n7.$($i).5.4.[DnsServerForwarder]`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo   
            $rmtOutput += (Get-DnsServerForwarder | Out-String -Width 2000)

            # 5.5.DNS DnsServerRootHint
            $rmtInfo = "`n7.$($i).5.5.[DnsServerRootHint]`n"
            Write-Host $rmtInfo; $rmtOutput += $rmtInfo   
            $rmtOutput += (Get-DnsServerRootHint | Out-String -Width 2000)
            return $rmtOutput
        } -ArgumentList $i
    }
}
Out-File -InputObject $output -FilePath $logFile -Encoding utf8