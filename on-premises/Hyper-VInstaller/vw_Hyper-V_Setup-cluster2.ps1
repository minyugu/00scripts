Get-PhysicalDisk |Ft Number,FriendlyName,SerialNumber,MediaType,BusType,CanPool,OperationalStatus,HealthStatus,Usage,@{L='Size GB'; E={$_.Size/1024/1024/1024}}
Get-Disk
Get-Disk | Where-Object IsSystem -eq $True
Get-Partition |ft DiskNumber,PartitionNumber,DriveLetter, {Get-Volume - FileSystem} ,@{L='Size GB'; E={[math]::Round(($_.Size/1024/1024/1024),2)}}, `
                    Type,IsSystem,IsBoot,IsActive,IsOffline,OperationalStatus

Get-Volume | FT DriveLetter,FriendlyName,FileSystemType,DriveType,HealthStatus,OperationalStatus, `
                @{L='SizeRemaining GB'; E={[math]::Round($_.SizeRemaining/1024/1024/1024,2)}}, `
                @{L='Size GB'; E={[math]::Round($_.Size/1024/1024/1024,2)}},@{L='AllocationUnitSize k'; E={$_.AllocationUnitSize/1024}}


# config Virtual Machine Disk 1 =================================
##[[[change]]] CSV disk id base on your enviroment ##
$vmCsvDisk1Numb = 4
##[[[change]]] CSV disk id base on your enviroment ##
Set-Disk -Number $vmCsvDisk1Numb -IsOffline $false
Initialize-Disk -Number $vmCsvDisk1Numb -PartitionStyle GPT
New-Partition –DiskNumber $vmCsvDisk1Numb -DriveLetter M -UseMaximumSize #-Size 10gb
Format-Volume -DriveLetter M -FileSystem NTFS -NewFileSystemLabel DC1-Data -AllocationUnitSize $(64*1024)


$vmCsvDisk1Numb = 3
##[[[change]]] CSV disk id base on your enviroment ##
Set-Disk -Number $vmCsvDisk1Numb -IsOffline $false
Initialize-Disk -Number $vmCsvDisk1Numb -PartitionStyle GPT
New-Partition –DiskNumber $vmCsvDisk1Numb -DriveLetter N -UseMaximumSize #-Size 10gb
Format-Volume -DriveLetter N -FileSystem NTFS -NewFileSystemLabel DC1-Log -AllocationUnitSize $(64*1024)


Get-ClusterAvailableDisk | Add-ClusterDisk



Enter-PSSession shadc2-hv-02

$Servers = @("sha-hv-02","shadc2-hv-02","shadc2-hv-01")

$Servers | foreach { Install-WindowsFeature -ComputerName $_ -Name Storage-Replica,FS-FileServer -IncludeManagementTools -restart }

#source
Get-WinEvent -ComputerName sha-hv-02 -ProviderName Microsoft-Windows-StorageReplica -max 4 | FL TimeCreated,ProviderName,Id,LevelDisplayName,Message 

#dest
Get-WinEvent -ComputerName sha-hv-02 -ProviderName Microsoft-Windows-StorageReplica | Where-Object {$_.ID -eq "1215"} | fl  TimeCreated,ProviderName,Id,LevelDisplayName,Message 

Get-WinEvent -ComputerName shadc2-hv-01 -ProviderName Microsoft-Windows-StorageReplica -max 6 | FL TimeCreated,ProviderName,Id,LevelDisplayName,Message 

(Get-SRGroup).Replicas | Select-Object currentLsn, LastInSyncTime, DataVolume, NumOfBytesRecovered, numofbytesremaining, ReplicationMode, ReplicationStatus | FT

while($true) {

 $v = (Get-SRGroup -Name "Replication 2").replicas | Select-Object numofbytesremaining
 [System.Console]::Write("Number of bytes remaining: {0}`r", $v.numofbytesremaining)
 Start-Sleep -s 5
}

Get-SRGroup
Get-SRPartnership
(Get-SRGroup).replicas



netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

(Get-SRGroup -Name "Replication 2").name = "Replcation DC2"

Get-SRGroup -Name "Replication 3" | Remove-SRGroup
Get-SRGroup -Name "Replication 4" | Remove-SRGroup

Diskspd.exe -c1g -d600 -W5 -C5 -b4k -t2 -o2 -r -w5 -i100 -j60 c:\test.dat
diskperf -Y

https://github.com/microsoft/diskspd/releases/download/v2.0.21a/DiskSpd.zip

get-clusternode

Get-SRGroup | ft Name, ComputerName, IsAutoFailiver, IsInpartnership, IsPrimary, IsSuspended, LastInSyncTime, LogType, LogVolume, LogSizeInBytes, ReplicationStatus
(Get-SRGroup).Replicas | Select-Object currentLsn, LastInSyncTime, DataVolume, NumOfBytesRecovered, NumofBytesRemaining, ReplicationMode, ReplicationStatus | FT
Get-SRPartnership

Get-ClusterGroup | ? {$_.GroupType -eq '119' }
Get-ClusterSharedVolume

(Get-SRGroup -Name "Replication 2").name = "Replcation DC2"
(Get-SRGroup -Name "Replication 2") | Set-SRGroup -

Get-ClusterFaultDomain

(Get-Cluster).AutoAssignNodeSite

Get-StorageJob

move-fleet
Diskspd.exe -c1g -d600 -W5 -C5 -b4k -t2 -o2 -r -w5 -j60 -i100 c:\test.dat
diskperf -Y
https://github.com/microsoft/diskspd/releases/download/v2.0.21a/DiskSpd.zip


New-SRPartnership -SourceComputerName sha-hv-01 -SourceRGName rg-dc1 -SourceVolumeName c:\ClusterStorage\dc1-data -SourceLogVolumeName N: `
    -DestinationComputerName shadc2-hv-01 -DestinationRGName rg-dc2 -DestinationVolumeName M: -DestinationLogVolumeName N: -LogType Raw



Add-ClusterSharedVolume -