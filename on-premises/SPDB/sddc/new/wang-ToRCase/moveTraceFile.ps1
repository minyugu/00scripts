###
# Sample:
# .\moveTraceFile.ps1 -clusterName @("POC01COMP01") -diskLetter d -diskSize 20
#
###


param
(
    [Parameter(Mandatory=$true, HelpMessage="input cluster name what need to check disk avaliale sapce.")]
#    [Alias('clusterNames')]
    [array]$clusterNames,
    
    [Parameter(Mandatory=$true)]
    [int]$diskLetter,
    
    [Parameter(Mandatory=$true)]
    [int]$diskSize
)

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
    
    foreach ($computenode in $total_nodes) {
    
        Invoke-Command -ComputerName $computenode -ScriptBlock {
            param([array]$sourceFileNames,[string]$destPath,[int]$diskSize,[string]$diskLetter)

                #disk D
                #Get-PSDrive -Name d
                $driveFreeSize = $null
                $driveFreeSize = $(Get-PSDrive -Name $diskLetter)
                if ($driveFreeSize.Free -le ($diskSize*1024*1024*1024)) {
                # net_netio$_.etl && smbserver$_.etl
                    # create folder
                    $destPathwithHostName = $destPath + "\" + $env:COMPUTERNAME
                    if (!(Test-Path $destPath)) { New-Item -Path $destPathwithHostName -ItemType Directory }
                    
                    # get first log file
                    $logs = @()
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