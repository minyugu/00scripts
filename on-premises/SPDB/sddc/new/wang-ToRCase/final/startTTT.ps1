# Get computer List
$compute1 = (Get-Cluster KF02-1D1E1F-COMPCL01 | Get-ClusterNode).Name
#$compute1 = @("AZ-KF02-WC122")
#$compute1 = @("AZ-KF02-WC122","AZ-KF02-WC123")

# Creat Job List
$jobList = @()  

#--------------------Start--------------------#

    #Start Captureing in computer node

foreach ($computenode in $compute1) {
    $job = Start-Job -ScriptBlock {  
        param($comp)      

        Invoke-Command -ComputerName $comp -ScriptBlock {
            #TTT trace
            cd D:\temp\ttt\TTDx64
            .\TTTracer.exe -initialize
            $vmmsPID = (Get-Process vmms).id 
            .\TTTracer.exe -attach $vmmsPID -dumpfull -noUI
            
            # cmd /k "C:\temp\startTTT.bat 12424"
            # cmd /k "C:\temp\stopTTT.bat"
        }
    } -ArgumentList $computenode  
    $jobList += $job 
}
#$jobList | Wait-Job