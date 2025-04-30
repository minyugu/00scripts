$diskLetter = "d"
$clusterNames = "POC01COMP01"
$diskSize = 20

$total_nodes = @()
foreach ($clusterName in $clusterNames) {
    $total_nodes += (Get-Cluster $clusterName | Get-ClusterNode).Name
}

$Round = 0
do {
    $Round++
    Write-Output ''
    Write-Output "Round $Round ************************************************************"

# start move etl file ********************************************************
# start move etl file ********************************************************
    $sourceFileNames = @("D:\net_netio*.etl", "D:\smbserver*.etl")

    $destPath = "\\AZ-POC01-WC001\c$\aa"
    $logFile = $destPath + "\copytrace.log"
    
    foreach ($computenode in $total_nodes) {
    
        Invoke-Command -ComputerName $computenode -ScriptBlock {
            param([array]$sourceFileNames,[string]$destPath,[int]$diskSize,[string]$diskLetter)

                #disk D
                #Get-PSDrive -Name d
                $driveFreeSize = $null
                $driveFreeSize = $(Get-PSDrive -Name $diskLetter)
                $driveFreeSize
                if ($driveFreeSize.Free -le ($diskSize*1024*1024*1024)) {
                "disksize1 : $diskSize"
                # net_netio$_.etl && smbserver$_.etl
                    # create folder
                    $destPathwithHostName = $destPath + "\" + $env:COMPUTERNAME
                    if (!(Test-Path $destPath)) { New-Item -Path $destPathwithHostName -ItemType Directory }
                    
                    # get first log file
                    $logs = @()
                    Out-File -FilePath $logFile
                    foreach ($sourceFileName in $sourceFileNames) {
                        $logs += Get-Item $sourceFileName
                    }
                    $logs | sort LastWriteTime | select -First 1 | Move-Item -Destination $destPathwithHostName
                }

        } -ArgumentList $sourceFileNames, $destPath, $diskSize, $diskLetter
    }

    Write-Output "Pause 30s ************************************************************"
    Start-Sleep -Seconds 30
} while (1 -eq 2)