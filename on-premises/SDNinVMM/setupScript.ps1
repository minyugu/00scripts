$server = "cfdcclu9204"
$server = "cfdcclu9205"
$server = "cfdcclu9902"

Enter-PSSession $server
Install-WindowsFeature -Name NetworkATC, Hyper-V, 'Failover-Clustering', 'Data-Center-Bridging' -IncludeManagementTools -Restart
# Restart-Computer -Force


# Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

# SET
$vSwitchNames = "ConvergedSwitch(management_compute)"
New-VMSwitch $vSwitchNames -NetAdapterName "pMgmtComp1","pMgmtComp2" -MinimumBandwidthMode Weight -AllowManagementOS $true -EnableEmbeddedTeaming $True -whatif
Rename-NetAdapter -Name "vEthernet (ConvergedSwitch(management_compute))" -NewName "vMGMT(ConvergedSwitch)"

<#
Get-VMSwitchTeam | Remove-VMSwitch
Get-VMSwitch  | Remove-VMSwitch

Get-VMNetworkAdapter -ManagementOS | foreach {Remove-VMNetworkAdapter $_}
#>

<#
# NetIntent 
$MgmtAdapterPropertyOverrides = New-NetIntentAdapterPropertyOverrides
$MgmtAdapterPropertyOverrides.NetworkDirectTechnology = 0
Add-NetIntent -Name Management_Compute -Management -Compute -AdapterName pMgmtComp1, pMgmtComp2 -AdapterPropertyOverrides $MgmtAdapterPropertyOverrides
#>


Install-WindowsFeature -ComputerName "Server1" -Name "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "FS-SMBBW", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-PowerShell", "NetworkATC", "Storage-Replica" -IncludeAllSubFeature -IncludeManagementTools


# S2D
# https://learn.microsoft.com/en-us/windows-server/storage/storage-spaces/deploy-storage-spaces-directss
# Fill in these variables with your values
$ServerList = "cfdcclu9204.msddc.corp", "cfdcclu9205.msddc.corp", "cfdcclu9902.msddc.corp"

foreach ($server in $serverlist) {
    Invoke-Command ($server) {
        # Check for the Azure Temporary Storage volume
        $azTempVolume = Get-Volume -FriendlyName "Temporary Storage" -ErrorAction SilentlyContinue
        If ($azTempVolume) {
            $azTempDrive = (Get-Partition -DriveLetter $azTempVolume.DriveLetter).DiskNumber
        }

# Clear and reset the disks
        $disks = Get-Disk | Where-Object {
            ($_.Number -ne $null -and $_.Number -ne $azTempDrive -and !$_.IsBoot -and !$_.IsSystem -and $_.PartitionStyle -ne "RAW")
        }
        $disks | ft Number,FriendlyName,OperationalStatus
        If ($disks) {
            Write-Host "This action will permanently remove any data on any drives other than the operating system boot drive!`nReset disks? (Y/N)"
            $response = read-host
            if ( $response.ToLower() -ne "y" ) { exit }

$disks | % {
            $_ | Set-Disk -isoffline:$false
            $_ | Set-Disk -isreadonly:$false
            $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -verbose
            $_ | Set-Disk -isreadonly:$true
            $_ | Set-Disk -isoffline:$true
        }

#Get-PhysicalDisk | Reset-PhysicalDisk

}
        Get-Disk | Where-Object {
            ($_.Number -ne $null -and $_.Number -ne $azTempDrive -and !$_.IsBoot -and !$_.IsSystem -and $_.PartitionStyle -eq "RAW")
        } | Group -NoElement -Property FriendlyName
    }
}


Enable-ClusterStorageSpacesDirect -CimSession ms-sddc-clu -WhatIf


# Set up the security certificates
New-SelfSignedCertificate -KeyUsageProperty All -Provider "Microsoft Strong Cryptographic Provider" -FriendlyName "MultiNodeNC" -DnsName @("nccluster.msddc.corp")




# S2D unClaimed disk
Get-PhysicalDisk | where {$_.size -eq 102005473280} | Select FriendlyName, CanPool, OperationalStatus, HealthStatus, Usage, size, AllocatedSize, uniqueID | ft
Get-StorageSubSystem Cluster* | Set-StorageHealthSetting -Name "System.Storage.PhysicalDisk.AutoPool.Enabled" -Value False
$disks = Get-PhysicalDisk -CanPool $true
Set-ClusterStorageSpacesDirectDisk -CanBeClaimed $false -PhysicalDisk $disks
Get-Disk | ? { $_.UniqueId -in ($disks).UniqueId } | Set-Disk -IsOffline $false



<#
Name:
Network Controller

ClientSecurityGroup:
MSDDC\Network Controller Users

DiagnosticLogShare:
\\ms-vmm.msddc.corp\NCLogs

DiagnosticLogSharePassword:
Pass@word

DiagnosticLogShareUsername:
MSDDC\msadmin


LocalAdmin:
.\Administrator

MgmtDomainAccountName:
MSDDC\msadmin

MgmtDomainAccountPassword:
Pass@word

MgmtDomainFQDN:
msddc.corp

MgmtSecurityGroup:
MSDDC\Network Controller Admins

RestEndPoint:
nccluster.msddc.corp

ServerCertificatePassword:
Pass@word

#>