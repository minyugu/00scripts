###############################
# file name: vm_Hyper-V_Setup.ps1
# verion: 1.3
#
#
# Please don't run the script directly. Instead copy the script block to PowerShell terminal, and run it one by one.
#
# Please change script block of "##[[[change]]] environment settings ###" base on your environment
# execute script block of "##[[[change]]] environment settings ###" in EVERY host.
#
##############################


##[[[change]]] environment settings #########################
$servers = @("Cicnbjsaedtj001","Cicnbjsaedtj002","Cicnbjsaedbx001","Cicnbjsaedbx002")

$mgmtSubnet = "10.120.88."
$clusterSubnet = "192.168.0."
$lmSubnet = "192.168.1."

$mgmtVlanId = 88
$clusterVlanId = 110
$lmVlanId = 29

# cluster ip address and name
$cnoIpaddress = "10.120.89.168"
$cnoName = "SAE4CICluVIP"

$vSwitchName = "40GbEConvergedSwitch"
$adapterNames = @("PCIe Slot 3 Port 1","PCIe Slot 3 Port 2","PCIe Slot 4 Port 1","PCIe Slot 4 Port 2")
$dnsServerAddress = @("10.120.137.11","10.120.137.12")
$gatewayAddress = "10.120.88.1"

##### start check system #######
# check network adpater
$adaptersInfos = Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-NetAdapter | Select-Object SystemName, name, InterfaceDescription, VlanID, @{l='IPAddress'; e={(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $_.ifIndex 2>null).IPAddress}}, `
                                @{l='Default Gateway'; e={((Get-NetIPConfiguration -InterfaceIndex $_.ifIndex 2>null).ipv4defaultgateway).NextHop}}, `
                                @{l='DNS Server'; e={((Get-NetIPConfiguration -InterfaceIndex $_.ifIndex 2>null).dnsserver | Where-Object {$_.addressFamily -eq 2}).ServerAddresses}}, `
                                ifIndex, MediaConnectionState, status, LinkSpeed, MacAddress #-AutoSize

}
$adaptersInfos |sort SystemName, name | Out-GridView

# confirm all share disks have been added in Host and keep all these disks offline
$diskInfos = Invoke-Command -ComputerName $servers -ScriptBlock {Get-Disk}
$diskINfos | Format-Table -AutoSize

##### end check system #######

###############################

Enter-PSSession Cicnbjsaedtj001
$ipAddressMgmt = "10.120.89.164"
$ipMaskMgmt = 23
$ipAddressCluster = "192.168.0.11"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.11"
$ipMaskLM = "24"

Enter-PSSession Cicnbjsaedtj002
$ipAddressMgmt = "10.120.89.165"
$ipMaskMgmt = 23
$ipAddressCluster = "192.168.0.12"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.12"
$ipMaskLM = "24"

Enter-PSSession Cicnbjsaedbx001
$ipAddressMgmt = "10.120.89.166"
$ipMaskMgmt = 23
$ipAddressCluster = "192.168.0.13"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.13"
$ipMaskLM = "24"

Enter-PSSession Cicnbjsaedbx002
$ipAddressMgmt = "10.120.89.167"
$ipMaskMgmt = 23
$ipAddressCluster = "192.168.0.14"
$ipMaskCluster = "24"
$ipAddressLm = "192.168.1.14"
$ipMaskLM = "24"

##[[[change]]] environment settings #########################

#################################### Networking ####################################
# Install windows feature
Install-WindowsFeature -Name Hyper-V,Failover-Clustering -IncludeManagementTools -Restart

# Switch Embedded Teaming (SET)=======================
Get-NetAdapter
## [[[change]]] -NetAdapterName “Ethernet”,"Ethernet 3" ##
New-VMSwitch $vSwitchName -NetAdapterName $adapterNames -MinimumBandwidthMode Weight -AllowManagementOS $true -EnableEmbeddedTeaming $True -whatif
## [[[change]]] -NetAdapterName “Ethernet”,"Ethernet 3" ##
# Set-VMSwitchTeam -Name $vSwitchName -TeamingMode SwitchIndependent -LoadBalancingAlgorithm HyperVPort
Get-VMSwitchTeam

# rename Management Nic and set QoS, disable VMQ=======================
$vnic = Get-VMNetworkAdapter -ManagementOS -Name $vSwitchNames
$vnic | Rename-VMNetworkAdapter -Newname "Management-102"
# $vnic | Set-VMNetworkAdapter -MinimumBandwidthWeight 5
# $vnic | Set-VMNetworkAdapter -VmqWeight 0 -WhatIf #if VM or host encounter performance issue.
# set vlan id
$vnic | Set-VMNetworkAdapterVlan -Access -VlanId $mgmtVlanId

# set ip###
New-NetIPAddress -InterfaceAlias "vEthernet (Management-102)" -IPAddress $ipAddressMgmt -PrefixLength $ipMaskMgmt -DefaultGateway $gatewayAddress -WhatIf
Set-DnsClientServerAddress -InterfaceAlias "vEthernet (Management-102)" -ServerAddresses $dnsServerAddress

Get-VMNetworkAdapter -ManagementOS -Name "Management-102"

# Start config adapter Cluster***********************
# Start config adapter Cluster***********************
$vnic = Get-NetAdapter -Name "PCIe Slot 2 Port 1"
$vnic | Rename-NetAdapter -NewName "Cluster-100"
$vnic |  Set-NetAdapter -VlanID $clusterVlanId

# set ip
new-NetIPAddress -InterfaceIndex $vnic.ifIndex -IPAddress $ipAddressCluster -PrefixLength $ipMaskCluster -WhatIf

# disable Netbios and DNS Registration
$adapter = ( gwmi win32_networkadapterconfiguration | Where-Object IPAddress -EQ $ipAddressCluster )
$adapter
$adapter.SetTcpIPNetbios(2) | Select-Object ReturnValue
$adapter.SetDynamicDNSRegistration($false) | Select-Object ReturnValue
# End config adapter Cluster***********************
# End config adapter Cluster***********************


# Start config adapter Live Migration=======================
# Start config adapter Live Migration=======================
$vnic = Get-NetAdapter -Name "PCIe Slot 2 Port 2"
$vnic | Rename-NetAdapter -NewName "LiveMigration-101"
$vnic |  Set-NetAdapter -VlanID $lmVlanId

# set ip
new-NetIPAddress -InterfaceIndex $vnic.ifIndex -IPAddress $ipAddressLm -PrefixLength $ipMaskLM -WhatIf

# disable Netbios and DNS Registration
$adapter = ( gwmi win32_networkadapterconfiguration | where IPAddress -EQ $ipAddressLm )
$adapter
$adapter.SetTcpIPNetbios(2) | Select ReturnValue
$adapter.SetDynamicDNSRegistration($false) | Select ReturnValue
# End config adapter Live Migration=======================
# End config adapter Live Migration=======================


# show VMNetworkAdapter config=======================
Get-VMNetworkAdapter -ManagementOS | ft Name, SwitchName, {$_.BandwidthSetting.MinimumBandwidthWeight}, BandwidthPercentage, VmqWeight, `
                                        @{l='OperationMode';e={$_.VlanSetting.OperationMode}}, @{l='AccessVlanId';e={$_.VlanSetting.AccessVlanId}}

$ipAddressMgmt = ((Get-NetIPAddress -InterfaceAlias "vEthernet (Management-102)").IPv4Address) | Where-Object {$_ -ne $null}
gwmi win32_networkadapterconfiguration | `
    where { ($_.IPAddress -EQ $ipAddressLm) -or ($_.IPAddress -EQ $ipAddressCluster) -or ($_.IPAddress -EQ $ipAddressMgmt) } | `
    ft IPAddress, FullDNSRegistrationEnabled, TcpipNetbiosOptions

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
Get-Partition |ft DiskNumber,PartitionNumber,DriveLetter, @{L='FileSystem'; E={(Get-Volume -DriveLetter $_.DriveLetter).FileSystem}}, `
                    @{L='Size GB'; E={[math]::Round(($_.Size/1024/1024/1024),2)}}, `
                    Type,IsSystem,IsBoot,IsActive,IsOffline,OperationalStatus

Get-Volume | FT DriveLetter,FriendlyName,FileSystemType,DriveType,HealthStatus,OperationalStatus, `
                @{L='SizeRemaining GB'; E={[math]::Round($_.SizeRemaining/1024/1024/1024,2)}}, `
                @{L='Size GB'; E={[math]::Round($_.Size/1024/1024/1024,2)}},@{L='AllocationUnitSize k'; E={$_.AllocationUnitSize/1024}}

# config Virtual Machine Disk 1 =================================
##[[[change]]] CSV disk id base on your enviroment ##
$vmCsvDisk1Numb = 3
##[[[change]]] CSV disk id base on your enviroment ##
Set-Disk -Number $vmCsvDisk1Numb -IsOffline $false -WhatIf
Initialize-Disk -Number $vmCsvDisk1Numb -PartitionStyle GPT -WhatIf
New-Partition -DiskNumber $vmCsvDisk1Numb -DriveLetter M -UseMaximumSize -WhatIf
Format-Volume -DriveLetter M -FileSystem NTFS -NewFileSystemLabel vmCsvDisk1 -AllocationUnitSize $(64*1024) -WhatIf


#################################### Cluster ####################################
# Test
Test-Cluster -Node $servers

# creat
New-Cluster -Name $cnoName -Node $servers -StaticAddress $cnoIpaddress -NoStorage

##### add share disk ================================
Get-ClusterAvailableDisk | ft name,@{L='Size GB'; E={$_.Size/1024/1024/1024}}

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
                         -Value ([String]::Join(“;”,(Get-ClusterNetwork | Where-Object {$_.Name -eq $((Get-ClusterNetwork | where {$_.Address -like "$($clusterSubnet)*"}).Name)}).ID))

#################################### Anti-virus excluding ####################################
Invoke-Command -ComputerName $servers -ScriptBlock {
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
}

# file share witness path
Set-ClusterQuorum -NodeAndFileShareMajority \\fileserver\fsw