<#
$i=0
$jobs = @()
do {
        #net_netio$_.etl
        $job = Start-Job -ScriptBlock { Start-Sleep 60 }
        $jobs += $job  
        $jobs
        get-job
} while ( 1 -eq 1)


$destPath = "\\AZ-POC01-WC001\c$\aa\"
if (!(Test-Path $destPath)) { New-Item -Path $destPath -ItemType Directory }
Get-Item .\net_netio*.etl | sort LastWriteTime | select -First 1 | Move-Item -Destination $destPath
$log1[0].LastWriteTime

Move-Item -Destination

Get-Item | where name .\net_netio*.etl 

#>
$DdiskWarringSize = 200

$total_nodes = (Get-Cluster "POC01COMP01" | Get-ClusterNode).Name

$sourceFileNames = @("D:\net_netio*.etl", "D:\smbserver*.etl")

    $destPath = "\\AZ-POC01-WC001\c$\aa"
    
    foreach ($computenode in $total_nodes) {
    
        $job = Invoke-Command -ComputerName $computenode -AsJob -ScriptBlock {
            param([array]$sourceFileNames,[string]$destPath,[int]$DdiskWarringSize)

                #disk D
                #Get-PSDrive -Name d
                $driveFreeSize = $null
                $driveFreeSize = $(Get-PSDrive -Name d)
                if ($driveFreeSize.Free -le ($DdiskWarringSize*1024*1024*1024)) {
                # net_netio$_.etl && smbserver$_.etl
                    # create folder
                    $destPathwithHostName = $destPath + "\" + $env:COMPUTERNAME
                    if (!(Test-Path $destPath)) { New-Item -Path $destPathwithHostName -ItemType Directory }
                    
                    # get first log file
                    $logs = @()
                    foreach ($sourceFileName in $sourceFileNames) {
                        $logs += Get-Item $sourceFileName
                    }
                    $logs | sort LastWriteTime | select -First 1 | Move-Item -Destination $destPath
                }

        } -ArgumentList $sourceFileNames, $destPath, $DdiskWarringSize
    }