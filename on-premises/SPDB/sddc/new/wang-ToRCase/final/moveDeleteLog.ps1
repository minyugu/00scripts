$compute1 = (Get-Cluster KF02-1D1E1F-COMPCL01 | Get-ClusterNode).Name
$s2d1 = (Get-Cluster KF02STOR01 | Get-ClusterNode).Name
$s2d2 = (Get-Cluster KF02STOR02 | Get-ClusterNode).Name

$total_nodes = @($compute1,$s2d1,$s2d2)

#$total_nodes = @($compute1)
# $total_nodes = (Get-Cluster POC01COMP01 | Get-ClusterNode).Name
$CdiskWarringSize = 30
$CdiskErrorSize = 15
$DdiskWarringSize = 30
$DdiskErrorSize = 15

$Round = 0
do {
    $Round++
    Write-Output ''
    Write-Output "Round $Round ************************************************************"
    foreach ($computenode in $total_nodes) {
    
        Invoke-Command -ComputerName $computenode -ScriptBlock {
            #disk C
            #Get-PSDrive -Name c
            $driveFreeSize = $null
            $driveFreeSize = $(Get-PSDrive -Name c)
            $driveFreeSize
            $Used:CdiskWarringSize
            if ($driveFreeSize.Free -le ($Using:CdiskErrorSize*1024*1024*1024)) {
                Write-Error "Error: disk free less than $($Using:CdiskErrorSize)GB"
            } elseif ($driveFreeSize.Free -le ($Using:CdiskWarringSize*1024*1024*1024)) {
                Write-Warning "Warring: disk free less than $($Using:CdiskWarringSize)GB"
            }
            #disk D
            #Get-PSDrive -Name d
            $driveFreeSize = $null
            $driveFreeSize = $(Get-PSDrive -Name d)
            $driveFreeSize
            if ($driveFreeSize.Free -le ($Using:DdiskErrorSize*1024*1024*1024)) {
                Write-Error "Error: disk free less than $($Using:DdiskErrorSize)GB"
            } elseif ($driveFreeSize.Free -le ($Using:DdiskWarringSize*1024*1024*1024)) {
                Write-Warning "Warring: disk free less than $($Using:DdiskWarringSize)GB"

            }
            Write-Output '================================================================'
        }
    }
    Write-Output "Pause 30s ************************************************************"
    Start-Sleep -Seconds 30
} while (1 -eq 1)

#--------------------move--------------------#
    #move logs from d:\ to c:\ on Storage node

<#=====================================
$S2dnodes = @($s2d1,$s2d2)

foreach ($computenode in $S2dnodes) {
     $job = Start-Job -ScriptBlock {  
        param($comp)  

        Invoke-Command -ComputerName $comp -ScriptBlock {
	        hostname
        #net_netio$_.etl
            $logs1 = 1..5|%{Get-Item D:\net_netio$_.etl}  
            $logs1|foreach{Move-Item $_ -Destination c:\}
         
        # smbserver$_.etl          
            $logs2 = 1..5|%{Get-Item D:\smbserver$_.etl}  
            $logs2|foreach{Move-Item $_ -Destination c:\}
            
        }
    } -ArgumentList $computenode  
    $jobList += $job 
}
$jobList | Wait-Job
========================================#>




#--------------------Check log file 1--------------------#
##check logfiles

foreach ($computenode in $compute1) {
        #$computenode = "AZ-KF02-WC101"
        Invoke-Command $computenode -ScriptBlock {
            
            hostname          
            Get-ChildItem D:\temp\*.etl
            Get-ChildItem D:\*.etl
            Get-ChildItem D:\temp\ttt\TTDx64\vmms*.run
            Write-Output "=============="
        }
}





#--------------------Delete computer log--------------------#
    #Delete logs in computer node
##check logfiles

<#=====================================

foreach ($computenode in $compute1) {
        #$computenode = "AZ-KF02-WC101"
        Invoke-Command $computenode -ScriptBlock {
            
            hostname            
            #Get-ChildItem D:\temp\*.etl | Remove-Item
            #Get-ChildItem D:\*.etl | Remove-Item
            Get-ChildItem D:\temp\ttt\TTDx64\vmms*.run | Remove-Item
        }
}



========================================#>

#--------------------Delete logs in S2D1--------------------#
<#=====================================
##check logfiles

foreach ($computenode in $s2d1) {

        Invoke-Command $computenode -ScriptBlock {
            
            hostname            
            Get-ChildItem D:\*.etl 
        }
}   

##delete-logfiles
foreach ($computenode in $s2d2) {

        Invoke-Command $computenode -ScriptBlock {
            
            hostname            
            Get-ChildItem D:\*.etl -Recurse | Remove-Item

        }
}

========================================#>