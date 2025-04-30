##[[[change]]] environment settings #########################
$servers = @("Cicnbjsaedtj001","Cicnbjsaedtj002","Cicnbjsaedbx001","Cicnbjsaedbx002")

$primarySiteName = "DC1"
$primarySiteDesc = "Primary"
$primarySiteLocation = "Chaoyang District"
$secondarySiteName = "DC2"
$secondarySiteDesc = "Secondary"
$secondarySiteLocation = "Shunyi District"

$mgmtSubnet = "10.120.89."
$clusterSubnet = "192.168.0."
$lmSubnet = "192.168.1."

$mgmtVlanId = 88
$clusterVlanId = 88
$lmVlanId = 88

# cluster ip address and name
$cnoIpaddress = "10.120.89.168"
$cnoName = "SAE4CIClusterVIP"

$vSwitchName = "Host20GbEConvergedSwitch"
$adapterNames = @("pNIC5","pNIC6")

##### start check system #######
# check network adpater
$adaptersInfos = Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-NetAdapter | select SystemName, name, InterfaceDescription, VlanID, @{l='IPAddress'; e={(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $_.ifIndex 2>null).IPAddress}}, `
                                @{l='Default Gateway'; e={((Get-NetIPConfiguration -InterfaceIndex $_.ifIndex 2>null).ipv4defaultgateway).NextHop}}, `
                                @{l='DNS Server'; e={((Get-NetIPConfiguration -InterfaceIndex $_.ifIndex 2>null).dnsserver | where {$_.addressFamily -eq 2}).ServerAddresses}}, `
                                ifIndex, MediaConnectionState, status, LinkSpeed, MacAddress #-AutoSize

}
$adaptersInfos |sort SystemName, name | Out-GridView

# confirm all share disks have been added in OS and keep all these disks offline
Invoke-Command -ComputerName $servers -ScriptBlock {Get-Disk}

##### end check system #######

###############################

# Enter-PSSession Cicnbjsaedtj001
$ipAddressCluster = "192.168.0.11"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.11"
$ipMaskLM = "24"

Enter-PSSession Cicnbjsaedtj002
$ipAddressCluster = "192.168.0.12"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.12"
$ipMaskLM = "24"

Enter-PSSession Cicnbjsaedbx001
$ipAddressCluster = "192.168.0.13"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.13"
$ipMaskLM = "24"

Enter-PSSession Cicnbjsaedbx002
$ipAddressCluster = "192.168.0.14"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.14"
$ipMaskLM = "24"

##[[[change]]] environment settings #########################

#################################### Networking ####################################
# rename physic network adpter
Rename-NetAdapter -Name "Ethernet" -NewName "pNIC1"
Rename-NetAdapter -Name "Ethernet" -NewName "pNIC2"
Rename-NetAdapter -Name "Ethernet" -NewName "pNIC3"
Rename-NetAdapter -Name "Ethernet" -NewName "pNIC4"
Rename-NetAdapter -Name "Ethernet" -NewName "pNIC5"
Rename-NetAdapter -Name "Ethernet" -NewName "pNIC6"

# comfirm tcp Chimneys disabled
Get-NetOffloadGlobalSetting
# Set-NetOffloadGlobalSetting -Chimney Disabled

# netsh int tcp show global
# netsh int tcp set global Chimney=disabled

# disable VMQ
# Disable VMQ in Physic Nic (Driver Advance),if VM or host encounter performance issue.
Get-NetAdapterVmq
# Disable-NetAdapterVmq -Name “Ethernet”
# Disable-NetAdapterVmq -Name “Ethernet 2”

# enable SR-IOV
# Enable SR-IOV in Physic Nic (Driver Advance)installinstall
Get-NetAdapterSriov
Get-NetAdapterSriov | Enable-NetAdapterSriov
# Enable-NetAdapterSriov -Name @("pNIC1", "pNIC2")

# Install
Install-WindowsFeature -Name Hyper-V,Failover-Clustering -IncludeManagementTools -Restart
Get-WindowsFeature -Name Hyper-V,Failover-Clustering

# Switch Embedded Teaming (SET)=======================
Get-NetAdapter
## [[[change]]] -NetAdapterName “Ethernet”,"Ethernet 3" ##
New-VMSwitch $vSwitchName -NetAdapterName $adapterNames -MinimumBandwidthMode Weight -AllowManagementOS $true -EnableEmbeddedTeaming $True -EnableIov $true -whatif
## [[[change]]] -NetAdapterName “Ethernet”,"Ethernet 3" ##
Set-VMSwitchTeam -Name $vSwitchName -TeamingMode SwitchIndependent -LoadBalancingAlgorithm HyperVPort
Get-VMSwitchTeam

# rename Management Nic and set QoS, disable VMQ=======================
$vnic = Get-VMNetworkAdapter -ManagementOS -Name $vSwitchNames
$vnic | Rename-VMNetworkAdapter -Newname "Management-102"
# $vnic | Set-VMNetworkAdapter -MinimumBandwidthWeight 5
# $vnic | Set-VMNetworkAdapter -VmqWeight 0 -WhatIf #if VM or host encounter performance issue.
# set vlan id
$vnic | Set-VMNetworkAdapterVlan -Access -VlanId $mgmtVlanId

####### remove physic network adapter VlanId
Set-NetAdapter -Name "pNIC5" -VlanID 0 -WhatIf
####### remove physic network adapter VlanId

Get-VMNetworkAdapter -ManagementOS -Name "Management-102"

# create adapter Cluster=======================
Add-VMNetworkAdapter –ManagementOS –Name “Cluster-100” -SwitchName $vSwitchName -whatif
$vnic = Get-VMNetworkAdapter -ManagementOS -Name "Cluster-100"
# $vnic | Set-VMNetworkAdapter –MinimumBandwidthWeight 15
# $vnic | Set-VMNetworkAdapter -VmqWeight 0 -WhatIf #if VM or host encounter performance issue.
$vnic | Set-VMNetworkAdapterVlan -Access -VlanId $clusterVlanId

# set ip
New-NetIPAddress -InterfaceAlias "vEthernet (Cluster-100)" -IPAddress $ipAddressCluster -PrefixLength $ipMaskCluster -WhatIf

# disable Netbios and DNS Registration
$adapter = ( gwmi win32_networkadapterconfiguration | where IPAddress -EQ $ipAddressCluster )
$adapter
$adapter.SetTcpIPNetbios(2) | Select ReturnValue
$adapter.SetDynamicDNSRegistration($false) | Select ReturnValue

# create adapter Live Migration=======================
Add-VMNetworkAdapter –ManagementOS –Name “LiveMigration-101” -SwitchName $vSwitchName -whatif
# $vnic = Get-VMNetworkAdapter -ManagementOS -Name "LiveMigration-101"
# $vnic | Set-VMNetworkAdapter –MinimumBandwidthWeight 30
# $vnic | Set-VMNetworkAdapter -VmqWeight 0 -WhatIf #if VM or host encounter performance issue.
$vnic | Set-VMNetworkAdapterVlan -Access -VlanId $lmVlanId

# set ip
New-NetIPAddress -InterfaceAlias "vEthernet (LiveMigration-101)" -IPAddress $ipAddressLm -PrefixLength $ipMaskLM -WhatIf

# disable Netbios and DNS Registration
$adapter = ( gwmi win32_networkadapterconfiguration | where IPAddress -EQ $ipAddressLm )
$adapter
$adapter.SetTcpIPNetbios(2) | Select ReturnValue
$adapter.SetDynamicDNSRegistration($false) | Select ReturnValue

 # show VMNetworkAdapter config=======================
Get-VMNetworkAdapter -ManagementOS | ft Name, SwitchName, {$_.BandwidthSetting.MinimumBandwidthWeight}, BandwidthPercentage, VmqWeight, `
                                        @{l='OperationMode';e={$_.VlanSetting.OperationMode}}, @{l='AccessVlanId';e={$_.VlanSetting.AccessVlanId}}

$ipAddressMgmt = ((Get-NetIPAddress -InterfaceAlias "vEthernet (Management-102)").IPv4Address) | Where-Object {$_ -ne $null}
gwmi win32_networkadapterconfiguration | `
    where { ($_.IPAddress -EQ $ipAddressLm) -or ($_.IPAddress -EQ $ipAddressCluster) -or ($_.IPAddress -EQ $ipAddressMgmt) } | `
    ft IPAddress, FullDNSRegistrationEnabled, TcpipNetbiosOptions

## create guest switch
New-VMSwitch "Guest40GbEConvergedSwitch" -NetAdapterName @("pNIC1","pNIC2","pNIC3","pNIC4") -MinimumBandwidthMode Weight -AllowManagementOS $false -EnableEmbeddedTeaming $True -EnableIov $true -whatif

# Shutdown /r

#################################### check network and win feature ###################################
# Exit

######### get system boot info #########
Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-CimInstance -ClassName win32_operatingsystem | ft csname,lastbootuptime 
} -HideComputerName
#########

Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-WindowsFeature -Name Hyper-V,Failover-Clustering # | ft Name, InstallState, PSComputerName
}

Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-VMNetworkAdapter -ManagementOS | sort Name | ft Name, SwitchName, {$_.BandwidthSetting.MinimumBandwidthWeight}, BandwidthPercentage, VmqWeight, ComputerName, `
                                        @{l='OperationMode';e={$_.VlanSetting.OperationMode}}, @{l='AccessVlanId';e={$_.VlanSetting.AccessVlanId}}
}

Invoke-Command -ComputerName $servers -ScriptBlock {
    gwmi win32_networkadapterconfiguration | where { ($_.IPAddress -like "$($Using:mgmtSubnet)*") -or ($_.IPAddress -like "$($Using:clusterSubnet)*") -or ($_.IPAddress -like "$($Using:lmSubnet)*")} | `
                                                sort IPAddress | ft IPAddress, FullDNSRegistrationEnabled, TcpipNetbiosOptions, PSComputerName
}

#################################### Storages ###################################
# just run in one node to bring disk online, patation and formart
# check disk
Get-PhysicalDisk |Ft Number,FriendlyName,SerialNumber,MediaType,BusType,CanPool,OperationalStatus,HealthStatus,Usage,@{L='Size GB'; E={$_.Size/1024/1024/1024}}
Get-Disk
Get-Disk | Where-Object IsSystem -eq $True
Get-Partition |ft DiskNumber,PartitionNumber,DriveLetter, {Get-Volume - FileSystem} ,@{L='Size GB'; E={[math]::Round(($_.Size/1024/1024/1024),2)}}, `
                    Type,IsSystem,IsBoot,IsActive,IsOffline,OperationalStatus

Get-Volume | FT DriveLetter,FriendlyName,FileSystemType,DriveType,HealthStatus,OperationalStatus, `
                @{L='SizeRemaining GB'; E={[math]::Round($_.SizeRemaining/1024/1024/1024,2)}}, `
                @{L='Size GB'; E={[math]::Round($_.Size/1024/1024/1024,2)}},@{L='AllocationUnitSize k'; E={$_.AllocationUnitSize/1024}}

<# using file share witness instead of Quorum Disk

# config Quorum Disk =================================
##[[[change]]] Quorum disk id base on your enviroment ##
$QuorumDiskNumb = 2
##[[[change]]] Quorum disk id base on your enviroment ##
Set-Disk -Number $QuorumDiskNumb -IsOffline $false -WhatIf
Initialize-Disk -Number $QuorumDiskNumb -PartitionStyle MBR -WhatIf
New-Partition –DiskNumber $QuorumDiskNumb -DriveLetter Q -UseMaximumSize -WhatIf #-Size 10gb
Format-Volume -DriveLetter Q -FileSystem NTFS -NewFileSystemLabel QuorumDisk -WhatIf

#>

# config Virtual Machine Disk 1 =================================
##[[[change]]] CSV disk id base on your enviroment ##
$vmCsvDisk1Numb = 1
##[[[change]]] CSV disk id base on your enviroment ##
Set-Disk -Number $vmCsvDisk1Numb -IsOffline $false -WhatIf
Initialize-Disk -Number $vmCsvDisk1Numb -PartitionStyle GPT -WhatIf
New-Partition –DiskNumber $vmCsvDisk1Numb -DriveLetter M -UseMaximumSize -WhatIf #-Size 10gb
Format-Volume -DriveLetter M -FileSystem NTFS -NewFileSystemLabel vmCsvDisk1 -AllocationUnitSize $(64*1024) -WhatIf


#################################### Cluster ####################################
# Test
Test-Cluster -Node $servers

# creat
New-Cluster -Name $cnoName -Node $servers –StaticAddress $cnoIpaddress -NoStorage

##### add share disk ================================
Get-ClusterAvailableDisk | ft name,@{L='Size GB'; E={$_.Size/1024/1024/1024}}

<# using file share witness instead of Quorum Disk

# add Quorum Disk
$ClusterQuorumDiskName = "Cluster Disk - Quorum"
$ClusterQuorumDisk = Get-Disk -Number $QuorumDiskNumb | Add-ClusterDisk 
$ClusterQuorumDisk.Name = $ClusterQuorumDiskName
$ClusterQuorumDisk
Set-ClusterQuorum -DiskWitness $ClusterQuorumDiskName

#>

# add VM Disk
$ClusterVMDisk1Name = "Cluster Disk - VM 1"
$ClusterVMDisk1 = Get-Disk -Number $vmCsvDisk1Numb | Add-ClusterDisk 
$ClusterVMDisk1.Name = $ClusterVMDisk1Name
$ClusterVMDisk1
# add disk to CSV
$ClusterVMDisk1 | Add-ClusterSharedVolume
Get-ClusterSharedVolume

# check CSV cache enabled
Get-ClusterSharedVolume | get-ClusterParameter EnableBlockCache
 (Get-Cluster). BlockCacheSize

# set default VM and VDisk Location
# Set-VMHost -ComputerName $servers -VirtualHardDiskPath "C:\ClusterStorage\Volume1" -VirtualMachinePath "C:\ClusterStorage\Volume1"

##### change cluster network ================================
Get-ClusterNetwork |ft Name,Role,Address,AddressMask,Ipv4Addresses,Ipv4PrefixLengths,AutoMetric,Metric,State

(Get-ClusterNetwork | where {$_.Address -like "$($mgmtSubnet)*"}).Name = "Cluster Network - Management-102"

(Get-ClusterNetwork | where {$_.Address -like "$($clusterSubnet)*"}).Name = "Cluster Network - Cluster-100"

(Get-ClusterNetwork | where {$_.Address -like "$($lmSubnet)*"}).Name = "Cluster Network - LiveMigration-101"

# confirm live migration uesing 'compression'
Get-VMHost |fl VirtualMachineMigrationPerformanceOption
# Set-VMHost -VirtualMachineMigrationPerformanceOption Compression


################ Set Live Migration Network ###################
# GUI
# In a cluster, the Live Migration network is set from the Failover Clustering console. 
# Right click on Networks and choose "Live Migration Settings". Select the network "Cluster Network - LiveMigration-101" to use as Live Migration
################ Set Live Migration Network ###################

Get-ClusterResourceType -Name “Virtual Machine” | Get-ClusterParameter

Get-ClusterResourceType -Name “Virtual Machine” | `
    Set-ClusterParameter -Name MigrationExcludeNetworks `
                         -Value ([String]::Join(“;”,(Get-ClusterNetwork | Where-Object {$_.Name -ne $((Get-ClusterNetwork | where {$_.Address -like "$($lmSubnet)*"}).Name)}).ID))

#################################### Anti-virus excluding ####################################

# cluster
Add-MpPreference -ExclusionPath 'C:\Windows\Cluster'
Add-MpPreference -ExclusionProcess 'C:\Windows\Cluster\clussvc.exe'
Add-MpPreference -ExclusionProcess 'C:\Windows\Cluster\rhs.exe'

# hyper-v
Add-MpPreference -ExclusionPath 'C:\ClusterStorage'

Add-MpPreference -ExclusionExtension @('vhd','vhdx','avhd','avhdx','vhds','vhdpmem','iso','rct','mrt','vsv','bin','xml','vmcx','vmrs','vmgs')

Add-MpPreference -ExclusionProcess 'C:\Windows\System32\Vmms.exe'
Add-MpPreference -ExclusionProcess 'C:\Windows\System32\Vmwp.exe'
Add-MpPreference -ExclusionProcess 'C:\Windows\System32\Vmcompute.exe'


# file share witness path
The path of the \Cluster folder on the quorum hard disk.

<# disable for this project scenario

#################################### Configure stretch cluster site awareness ####################################

# check Fault domain awareness is enabled (1=enabled, 0=disabled)
(Get-Cluster).AutoAssignNodeSite
(Get-Cluster).ResiliencyDefaultPeriod
(Get-Cluster).ResiliencyLevel

New-ClusterFaultDomain -Name $primarySiteName -Type Site -Description $primarySiteDesc -Location $primarySiteLocation
New-ClusterFaultDomain -Name $secondarySiteName -Type Site -Description $secondarySiteDesc -Location $secondarySiteLocation

# New-ClusterFaultDomain -Type Rack -Name "Rack A"
# New-ClusterFaultDomain -Type Rack -Name "Rack B"
Set-ClusterFaultDomain -Name $servers[0] -Parent $primarySiteName
Set-ClusterFaultDomain -Name $servers[1] -Parent $primarySiteName
Set-ClusterFaultDomain -Name $servers[2] -Parent $secondarySiteName
Set-ClusterFaultDomain -Name $servers[3] -Parent $secondarySiteName

Get-ClusterFaultDomain


# DC1 is preferred for node ownership of the source VMs
(Get-Cluster).PreferredSite = $primarySiteName

# Configure VM resiliency so that guests do not pause for long during node failures. Instead, they failover to the secondary site within 10 seconds
# (Get-Cluster).ResiliencyDefaultPeriod=10


#################################### other command ####################################
# New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 172.30.200.101 -PrefixLength 16 -DefaultGateway 172.30.0.1 -WhatIf
# Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 172.30.12.11 -WhatIf
# Set-WinDefaultInputMethodOverride -InputTip "0409:00000409"
# Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
# Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

#>