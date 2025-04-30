# Get computer List
$compute1 = (Get-Cluster KF02-1D1E1F-COMPCL01 | Get-ClusterNode).Name
#$compute1 = @("AZ-KF02-WC122")
#$compute1 = @("AZ-KF02-WC122","AZ-KF02-WC123")

$s2d1 = (Get-Cluster KF02STOR01 | Get-ClusterNode).Name
$s2d2 = (Get-Cluster KF02STOR02 | Get-ClusterNode).Name
#$s2d1 = @("AZ-KF02-WS211")
#$s2d1 = @("AZ-KF02-WS211","AZ-KF02-WS212")
#$s2d2 = @("AZ-KF02-WS112","AZ-KF02-WS113")

# Creat Job List
$jobList = @()  

#--------------------Copy--------------------#

# Copy Scripts

<#====================================

$comFile1 = "C:\temp\tools0926\smbclient.bat"
$comFile2 = "C:\temp\tools0926\smbclient - pause.bat"
$s2dFile1 = "C:\temp\tools0926\smbserver.bat"
$s2dFile2 = "C:\temp\tools0926\smbserver - pause.bat"
#$TttStartFile = "C:\temp\tools0926\startTTT.bat"
#$TttStopFile = "C:\temp\tools0926\stopTTT.bat"

$compute1|%{
        Write-Host $_
        Copy-Item $comFile1 "\\$_\c$\temp\" 
        Copy-Item $comFile2 "\\$_\c$\temp\"
        #Copy-Item $TttStartFile "\\$_\c$\temp\" 
        #Copy-Item $TttStopFile "\\$_\c$\temp\" 
}

$s2d1|%{
        Write-Host $_
        Copy-Item $s2dFile1 "\\$_\c$\temp\"
        Copy-Item $s2dFile2 "\\$_\c$\temp\" 
}

$s2d2|%{
        Write-Host $_
        Copy-Item $s2dFile1 "\\$_\c$\temp\"
        Copy-Item $s2dFile2 "\\$_\c$\temp\" 
}

====================================#>

#--------------------Start--------------------#

    #Start Captureing in computer node

foreach ($computenode in $compute1) {
    $job = Start-Job -ScriptBlock {  
        param($comp)      

        Invoke-Command -ComputerName $comp -ScriptBlock {
            #wpr trace
            cd C:\windows\system32
            .\wpr.exe -start D:\temp\HyperVTraceProfile.wprp!AllHypTraces -filemode -recordtempto D:\temp

            ##vmltrace
            # cd C:\temp\tools0926\VmlTrace
            # .\VmlTrace.exe /m a /f all all /u /z 4096 /i  
            
            C:\temp\smbclient.bat
            #logman create trace "net_netio" -ow -o C:\temp\tools0926\t10\net_netio.etl -p "Microsoft-Windows-TCPIP" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode newlife -max 4096 -ets
            #logman update trace "net_netio" -p "Microsoft-Windows-SMBDirect" 0xffffffffffffffff 0xff -ets
            
            #cd C:\temp\tools0926\t10
            #.\t10.cmd clion circ:6000
        }
    } -ArgumentList $computenode  
    $jobList += $job 
}
# $jobList | Wait-Job

    #Start Capturing in S2D1
    
foreach ($computenode in $s2d1) {

    $job = Start-Job -ScriptBlock {
      
        param($comp)     

        Invoke-Command -ComputerName $comp -ScriptBlock {
        
            #cd C:\temp\tools0926\t10
            #.\t10.cmd srvon circ:6000
        
            C:\temp\smbserver.bat
            #logman create trace "net_netio" -ow -o C:\temp\tools0926\t10\net_netio.etl -p "Microsoft-Windows-TCPIP" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode newlife -max 4096 -ets
            #logman update trace "net_netio" -p "Microsoft-Windows-SMBDirect" 0xffffffffffffffff 0xff -ets
        
        }
    } -ArgumentList $computenode
      
    $jobList += $job 
}
# $jobList | Wait-Job

    #Start Capturing in S2D2


foreach ($computenode in $s2d2) {

    $job = Start-Job -ScriptBlock {
      
        param($comp)     

        Invoke-Command -ComputerName $comp -ScriptBlock {
            
            #cd C:\temp\tools0926\t10
            #.\t10.cmd srvon circ:6000
            C:\temp\smbserver.bat
            #logman create trace "net_netio" -ow -o C:\temp\tools0926\t10\net_netio.etl -p "Microsoft-Windows-TCPIP" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode newlife -max 4096 -ets
            #logman update trace "net_netio" -p "Microsoft-Windows-SMBDirect" 0xffffffffffffffff 0xff -ets
        
        }
    } -ArgumentList $computenode  

    $jobList += $job 
}
# $jobList | Wait-Job