#--------------------Stop----------------------#
# $compute1 = @("AZ-KF02-WC122","AZ-KF02-WC123","AZ-KF02-WC222")
# $compute1 = (Get-Cluster POC01COMP01 | Get-ClusterNode).Name
$StopHangHost = $false
#$StopHangHost = $true
$hangHostName = "AZ-POC01-WC002"


# remove hanghost from computer1 array or set hanghost as computer1 array=================================
If ($StopHangHost -eq $true)
{
    $newCompute1 = @($hangHostName)
} elseif ($StopHangHost -eq $false) {
    $newCompute1 = $compute1 -ne $hangHostName
}



#Stop Captureing in computer node=================================
foreach ($computenode in $newCompute1) {
    $job = Start-Job -ScriptBlock {  

        param($comp) 

        Invoke-Command -ComputerName $comp -ScriptBlock {
            #stop TTT trace
            cd D:\temp\ttt\TTDx64
            .\TTTracer.exe -stop all

            #stop wpr trace
            cd C:\windows\system32
            .\wpr.exe -stop D:\temp\hypervtrace.etl

            ##stop vmltrace
            # cd C:\temp\tools0926\VmlTrace
            #.\VmlTrace.exe /s

            logman stop "net_netio" -ets
            & 'C:\temp\smbclient - pause.bat'

        }
    } -ArgumentList $computenode  

    $jobList += $job
}
$jobList | Wait-Job


#**********************************************************************************************************************
#**********************************************************************************************************************

#Stop Capturing in S2D1========================================

foreach ($computenode in $s2d1) {

     $job = Start-Job -ScriptBlock {  

        param($comp)  

        Invoke-Command -ComputerName $comp -ScriptBlock {

            logman stop "net_netio" -ets
            & 'C:\temp\smbserver - pause.bat'

        }
    } -ArgumentList $computenode
      
    $jobList += $job 
}
$jobList | Wait-Job



#Stop Capturing in S2D2========================================

foreach ($computenode in $s2d2) {

     $job = Start-Job -ScriptBlock {  

        param($comp)

        Invoke-Command -ComputerName $comp -ScriptBlock {
        
            logman stop "net_netio" -ets
            & 'C:\temp\smbserver - pause.bat'

        }
    } -ArgumentList $computenode  

    $jobList += $job 
}
$jobList | Wait-Job