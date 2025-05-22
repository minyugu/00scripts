# https://learn.microsoft.com/en-us/system-center/vmm/sdn-port-acls?view=sc-vmm-2025

# Create a port ACL
New-SCPortACL -Name "ICMPAccess" -Description "PortACL to control ICMP access" -ManagedByNC

# Create a port ACL rule
$portACL = Get-SCPortACL -Name "RDPAccess"
New-SCPortACLRule -Name "AllowRDPAccess" -PortACL $portACL -Description "Allow RDP Rule from a subnet" `
    -Action Allow -Type Inbound -Priority 110 -Protocol Tcp -LocalPortRange 3389 -RemoteAddressPrefix 10.184.20.0/24

# Attach an ACL to a virtual network adapter
$vm = Get-SCVirtualMachine -Name “TenantVM”
$adapter = Get-SCvirtualNetworkAdapter -VM $vm

$portACL = Get-SCPortACL -Name "RDPAccess"
Set-SCVirtualNetworkAdapter -VirtualNetworkAdapter $adapter -PortACL $portACL



 # Filter VMs where the custom property 'Environment' is 'Production'
$filteredVMs = $allVMs | Where-Object {
    $_.CustomProperty["ServerLocation"] -eq "DMZ"
}
 


## ACLs with Tags
#region 1.##### deny all inbound
# Create a port ACL
$portAllACL = New-SCPortACL -Name "ALLAccess" -Description "PortACL to control ALL access" -ManagedByNC

# Create a port ACL rule
$SCPortACLRule = New-SCPortACLRule -Name "DenyAllInBound" -PortACL $portAllACL -Description "Deny All In Bound access Rule" -Action Deny -Type Inbound -Priority 64499 -Protocol Any -LocalPortRange 0-65535

# Attach an ACL to a virtual network adapter
$adapter = Get-SCVirtualMachine -Name “vpc01-sub101-v1” | Get-SCvirtualNetworkAdapter
Set-SCVirtualNetworkAdapter -VirtualNetworkAdapter $adapter -PortACL $portAllACL 
#endregion 1.##### deny all inbound

#region 2.##### Allow InBound RDP from Internal tag VM
# Filter VMs where the custom property 'ServerLocation' is 'Internal'
$vmTagName = "ServerLocation"
$vmTagValue = "Internal"

# get port ACL
$portAllACL = get-SCPortACL -Name "ALLAccess"

# Create a port ACL rule
$filteredVMs = Get-SCVirtualMachine | Where-Object { $_.CustomProperty[$vmTagName] -eq $vmTagValue } 
$SCPortACLRule = New-SCPortACLRule -Name "AllowInBoundRDPfromInternal" -PortACL $portAllACL -Description "Allow InBound RDP from Internal tag VM" `
                                   -Action Allow -Type Inbound -Priority 110 -Protocol TCP -LocalPortRange 3389 -RemoteAddressPrefix $filteredVMs.VirtualNetworkAdapters.IPv4Addresses
#endregion 2.##### Allow InBound RDP from Internal tag VM


#region 3.##### Allow OutBound to DMZ tag VM

## deny all outbound
# Create a port ACL
$portAllACL = Get-SCPortACL -Name "ALLAccess"

# Create a port ACL rule
$SCPortACLRule = New-SCPortACLRule -Name "DenyAllOutBound" -PortACL $portAllACL -Description "Deny All Out Bound access Rule" -Action Deny -Type Outbound -Priority 64498 -Protocol Any -LocalPortRange 0-65535 

## Filter VMs where the custom property 'ServerLocation' is 'DMZ'
$vmTagName = "ServerLocation"
$vmTagValue = "DMZ"

# get port ACL
$portAllACL = get-SCPortACL -Name "ALLAccess"

# Create a port ACL rule
$filteredVMs = Get-SCVirtualMachine | Where-Object { $_.CustomProperty[$vmTagName] -eq $vmTagValue } 
$SCPortACLRule = New-SCPortACLRule -Name "AllowOutBoundToDMZ" -PortACL $portAllACL -Description "Allow OutBound traffice to DMZ tag VM" `
                                   -Action Allow -Type Outbound -Priority 120 -Protocol Any -RemoteAddressPrefix $filteredVMs.VirtualNetworkAdapters.IPv4Addresses 
#endregion 3.##### Allow OutBound to DMZ tag VM