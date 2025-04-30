###
# Sample:
# .\diskAvailableSpaceCheck.ps1 -clusterName @("POC01COMP01","POC01MGMT") -cwz 30 -cez 15 -dwz 30 -dez 15
#
# .\diskAvailableSpaceCheck.ps1 -clusterName @("POC01COMP01") -cwz 30 -cez 15 -dwz 300 -dez 150

# .\diskAvailableSpaceCheck.ps1 -clusterName KF02-1D1E1F-COMPCL01 -cwz 30 -cez 15 -dwz 200 -dez 50
# .\diskAvailableSpaceCheck.ps1 -clusterName @("KF02STOR01","KF02STOR02") -cwz 30 -cez 15 -dwz 35 -dez 15


# .\diskAvailableSpaceCheck.ps1 -clusterName KF02-1A1B1C-COMPCL01 -cwz 30 -cez 15 -dwz 200 -dez 50
###


param
(
    [Parameter(Mandatory=$true, HelpMessage="input cluster name what need to check disk avaliale sapce.")]
#    [Alias('clusterNames')]
    [array]$clusterNames,
    
    [Parameter(Mandatory=$false)]
    [Alias('cwz')]
    [int]$CdiskWarringSize=30,
    
    [Parameter(Mandatory=$false)]
    [Alias('cez')]
    [int]$CdiskErrorSize = 15,
        
    [Parameter(Mandatory=$false)]
    [Alias('dwz')]
    [int]$DdiskWarringSize = 200,

    [Parameter(Mandatory=$false)]
    [Alias('dez')]
    [int]$DdiskErrorSize = 50
)

$total_nodes = @()
foreach ($clusterName in $clusterNames) {
    $total_nodes += (Get-Cluster $clusterName | Get-ClusterNode).Name
}
#$CdiskWarringSize = 30
#$CdiskErrorSize = 15
#$DdiskWarringSize = 200
#$DdiskErrorSize = 50

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
            
            $fc = $host.UI.RawUI.ForegroundColor         

            if ($driveFreeSize.Free -le ($Using:CdiskErrorSize*1024*1024*1024)) {
                $host.UI.RawUI.ForegroundColor = 'red'
                $driveFreeSize
                $host.UI.RawUI.ForegroundColor = $fc
            } elseif ($driveFreeSize.Free -le ($Using:CdiskWarringSize*1024*1024*1024)) {
                $host.UI.RawUI.ForegroundColor = 'yellow'
                $driveFreeSize
                $host.UI.RawUI.ForegroundColor = $fc
            } else {
                $driveFreeSize
            }

            #disk D
            #Get-PSDrive -Name d
            $driveFreeSize = $null
            $driveFreeSize = $(Get-PSDrive -Name d)
            $warringError = $false
            if ($driveFreeSize.Free -le ($Using:DdiskErrorSize*1024*1024*1024)) {
                $host.UI.RawUI.ForegroundColor = 'red'
                $driveFreeSize
                $host.UI.RawUI.ForegroundColor = $fc
                
                $warringError = $true

            } elseif ($driveFreeSize.Free -le ($Using:DdiskWarringSize*1024*1024*1024)) {
                $host.UI.RawUI.ForegroundColor = 'yellow'
                $driveFreeSize
                $host.UI.RawUI.ForegroundColor = $fc
                
                $warringError = $true
            } else {
                $driveFreeSize
            }

            # move trace file net_netio$_.etl && smbserver$_.etl
        }
    }

    Write-Output "Pause 30s ************************************************************"
    Start-Sleep -Seconds 30
} while (1 -eq 1)
#