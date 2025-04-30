Connect-AzAccount -Environment AzureChinaCloud
Get-AzEnvironment | Select-Object -Property Name

# $120 Subscription
$TenantIdVSES = '43149fdb-048d-445c-8df1-8d4a8825e56c'
Connect-AzAccount -Tenant $TenantIdVSES

# $1000 Subscription
$TenantIdMS = '72f988bf-86f1-41af-91ab-2d7cd011db47'
Connect-AzAccount -Tenant $TenantIdMS

#environment
$location = 'eastasia'
$rgName = 'guest-configuration'
$vNetName = 'Vnet-GuestConfig'
$subnetName = 'default'

Get-AzLocation | Format-Table
Get-AzVMSize -Location $location

#get Image
Get-AzVMImagePublisher -Location $location | Where-Object {$_.PublisherName -like "*windows*" }
Get-AzVMImageOffer -Location $location -PublisherName 'MicrosoftWindowsServer'
Get-AzVMImageSku -Location $location -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' | Where-Object {$_.Skus -like "*2022*"}
$VMImages = Get-AzVMImage -Location $location -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus '2022-datacenter-azure-edition' -Version "latest"
$VMImages[0]

# Resource Group
$rg = @{
    Name = $rgName
    Location = $location
}
New-AzResourceGroup @rg

# Vnet=======================================================
$VnetAddressPrefix = '172.21.0.0/16'
$vnet = @{
    Name = $vNetName
    ResourceGroupName = $rgName
    Location = $location
    AddressPrefix = $VnetAddressPrefix
}
$virtualNetwork = New-AzVirtualNetwork @vnet

# Vnet-Subnet
$SubnetAddressPrefix = '172.21.0.0/24'
$subnet = @{
    Name = $subnetName
    VirtualNetwork = $virtualNetwork
    AddressPrefix = $SubnetAddressPrefix
}
$subnetConfig = Add-AzVirtualNetworkSubnetConfig @subnet

# Associate the subnet to the virtual network
$virtualNetwork | Set-AzVirtualNetwork

#======================================================Create VM
$vmName = 'GuestConfig-1'
$vmSize = 'Standard_B2ms'
$vmSize = 'Standard_D2as_v4'
$vmSize = 'Standard_D2s_v4'
$vmSize = 'Standard_D2s_v5'

# vm Image
$PublisherName = 'MicrosoftWindowsServer'
$Offer = 'WindowsServer'
$vmSKU = '2022-datacenter-azure-edition'
$imageVerion = '20348.350.2111030009'

# $image = Get-AzVMImage -Location $location -PublisherName $PublisherName -Offer $Offer -Sku $vmSKU -Version $imageVerion
# $vmSourceImage = Set-AzVMSourceImage -Id $image.id

# create Local Admin
$VMLocalAdminUser = "mygu"
$VMLocalAdminSecurePassword = ConvertTo-SecureString 'Pass@word20211207' -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($VMLocalAdminUser, $VMLocalAdminSecurePassword);

<#
$vmIMageurn = 'MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest'
$vm = @{
    ResourceGroupName = $rgName
    Location = $location
    Name = $vmName
    VirtualNetworkName = $vNetName
    SubnetName = $subnetName
    Size = $vmSize
    Image = $vmIMageurn
    Credential = $Credential
    OpenPorts = 43389
}
New-AzVM @vm -AsJob
#>

###################### vm Config ##################################

# vm Public IP
$PublicIp = New-AzPublicIpAddress -Name $($vmName+"-pip") -ResourceGroupName $rgName -Location $location -AllocationMethod Dynamic

# NSG
$nsg = @{
    Name = $($vmName+"-nic-nsg")
    ResourceGroupName = $rgName
    Location = $location
}

$NetworkSecurityGroup = New-AzNetworkSecurityGroup @nsg

# NSG Rule for RDP
$nsgRuleConfig = @{
    Name = 'allowCRDP'
    NetworkSecurityGroup = $NetworkSecurityGroup
    Protocol = 'TCP'
    Direction = 'Inbound'
    Priority                 = 101
    SourceAddressPrefix      = '*'
    SourcePortRange          = '*'
    DestinationAddressPrefix = '*'
    DestinationPortRange     = 43389
    Access = 'Allow'
}
  
Add-AzNetworkSecurityRuleConfig @nsgRuleConfig | Set-AzNetworkSecurityGroup
  
# vm Interface
$objVNet = Get-AzVirtualNetwork -Name $vNetName -ResourceGroupName $rgName
$objVNetSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $objVNet -Name $subnetName
$Nic = @{
    Name = $($vmName+"-nic")
    ResourceGroupName = $rgName
    Location = $location
    Subnet = $objVNetSubnet
    PublicIpAddress = $PublicIp
    NetworkSecurityGroup = $NetworkSecurityGroup
}
$NetworkInterface = New-AzNetworkInterface @Nic

# VM size and image
$VM = New-AzVMConfig -VMName $VMName -VMSize $vmSize -IdentityType SystemAssigned -Priority 'Spot' -MaxPrice -1 -EvictionPolicy Deallocate
$VM = Set-AzVMOperatingSystem -VM $VM -Windows -ComputerName $vmName -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate -TimeZone 'China Standard Time'
$VM = Add-AzVMNetworkInterface -VM $VM -Id $NetworkInterface.Id
$VM = Set-AzVMSourceImage -VM $VM -PublisherName $PublisherName -Offer $Offer -Skus $vmSKU -Version latest

New-AzVM -ResourceGroupName $rgName -Location $location -VM $VM -LicenseType 'Windows_Server' -Verbose

# Set Custom RDP Port for Windows
Invoke-AzVMRunCommand -ResourceGroupName $rgName -Name $VMName -CommandId 'SetRDPPort' -Parameter @{"RDPPort" = "43389"}

#======================================================End Create VM

# create DNS configuration for Private End Point====================================================
Connect-AzAccount -Subscription '07936935-5ab8-40b8-9c34-e097c4d462ea'
$dnsZone = Get-AzPrivateDnsZone -ResourceGroupName "ea-hci-matrix_group" -Name "privatelink.blob.core.windows.net"
$config = New-AzPrivateDnsZoneConfig -Name "mgblob" -PrivateDnsZoneId $dnsZone.ResourceId
New-AzPrivateDnsZoneGroup -ResourceGroupName "Management" -PrivateEndpointName "storage-private-endpoint" -name "dnsgroup1" -PrivateDnsZoneConfig $config -Force

Get-AzPrivateDnsZoneGroup -ResourceGroupName "Management" -PrivateEndpointName "storage-private-endpoint" 
Remove-AzPrivateDnsZoneGroup -ResourceGroupName "Management" -PrivateEndpointName "storage-private-endpoint" -Name 'default'

# Utilities---------------------------------------------------------------------------------------------------------------
Get-AzPublicIpAddress |Format-Table name, ipaddress
Get-AzEffectiveRouteTable -ResourceGroupName $rgName -NetworkInterfaceName $($vmName+"-nic")
# set BGInfo
Set-AzVMBgInfoExtension -ResourceGroupName "EA-HCI-MATRIX_GROUP" -VMName "ea-hci-matrix" -Name "BgInfoExtension" -TypeHandlerVersion "2.1" -Location "East Asia"

## 1============root management group role assignment
Get-AzRoleAssignment | where {$_.RoleDefinitionName -eq "User Access Administrator" `
  -and $_.SignInName -eq "mg@omygu.com" -and $_.Scope -eq "/"}
Remove-AzRoleAssignment -SignInName <username@example.com> `
  -RoleDefinitionName "User Access Administrator" -Scope "/"

new-AzRoleAssignment -SignInName 'mg@omygu.com' `
  -RoleDefinitionName 'Hierarchy Settings Administrator' -Scope "/"

remove-AzRoleAssignment -SignInName 'mg@omygu.com' `
  -RoleDefinitionName 'Hierarchy Settings Administrator' -Scope "/"
## 1============ End root management group role assignment

# deploy configuration extension for Windows
Set-AzVMExtension `
    -Publisher 'Microsoft.GuestConfiguration' `
    -Type 'ConfigurationforWindows' `
    -Name 'AzurePolicyforWindows' `
    -TypeHandlerVersion 1.0 `
    -ResourceGroupName $rgName `
    -Location $location `
    -VMName $vmName `
    -EnableAutomaticUpgrade $true

# 2================================== set default management group
$root_management_group_id = "Enter the ID of root management group"
$default_management_group_id = "Enter the ID of default management group (or use the same ID of the root management group)"

$body = '{
     "properties": {
          "defaultManagementGroup": "/providers/Microsoft.Management/managementGroups/' + $default_management_group_id + '",
          "requireAuthorizationForGroupCreation": true
     }
}'

$token = (Get-AzAccessToken).Token
$headers = @{"Authorization"= "Bearer $token"; "Content-Type"= "application/json"}
$uri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$root_management_group_id/settings/default?api-version=2020-05-01"

Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -Body $body
# 2================================== End set default management group

# system assigned
# Spot
# NSG

#### Cli ##########========================================================================================================================
$TenantIdVSES = '43149fdb-048d-445c-8df1-8d4a8825e56c'
# $1000 Subscription
$TenantIdMS = '72f988bf-86f1-41af-91ab-2d7cd011db47'
az login --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47
az account set --subscription "MG AIRS V2"
az account list --query "[].{Name:name, IsDefault:isDefault}" --out table

az vm image list --location eastus --output table
az vm image list --location eastasia --output table --publisher MicrosoftWindowsServer --offer WindowsServer --sku 2022 --all

az network nic show-effective-route-table \
    --resource-group learn-6b5dab6a-428f-4f16-8492-51c647f395ec \
    --name SalesVMVMNic \
    --output table

#Create custom role
az role definition create --role-definition "C:\MyGu\OneDrive\WorkData\My Documents\0 MS\.DevOps\Cloud Powershell\AzureVMOperator.json"

# connect to bastion via native client
az network bastion rdp --subscription "MG AIRS V2" --name "bastion-ea-01" --resource-group "rg-bastion" --target-resource-id "/subscriptions/07936935-5ab8-40b8-9c34-e097c4d462ea/resourceGroups/ea-hci-matrix_group/providers/Microsoft.Compute/virtualMachines/ea-hci-matrix"
#    --resource-port "43389"

az resource show --ids "/subscriptions/07936935-5ab8-40b8-9c34-e097c4d462ea/resourceGroups/ea-hci-matrix_group/providers/Microsoft.Compute/virtualMachines/ea-hci-matrix"

# Azure VM join AAD
az vm extension set --publisher Microsoft.Azure.ActiveDirectory --name AADLoginForWindows --resource-group ea-hci-matrix_group --vm-name ea-hci-matrix

# Databricks
databricks secrets create-scope --scope databricks-secret-scope --scope-backend-type AZURE_KEYVAULT --resource-id '/subscriptions/07936935-5ab8-40b8-9c34-e097c4d462ea/resourceGroups/Data/providers/Microsoft.KeyVault/vaults/kv-bigdate-01' --dns-name 'https://kv-bigdate-01.vault.azure.net/'

# Infrastructure as Code
git clone https://github.com/MicrosoftDocs/mslearn-host-domain-azure-dns.git

cd mslearn-host-domain-azure-dns
chmod +x setup.sh
./setup.sh

# enable featrue for Linux
https://docs.microsoft.com/en-us/learn/modules/control-network-traffic-flow-with-routes/6-exercise-route-traffic-through-nva

code cloud-init.txt
    #cloud-config
    package_upgrade: true
    packages:
    - inetutils-traceroute

az vm create \
    --resource-group learn-1b9d4314-34f2-4a10-b6f0-7fec0626f690 \
    --name public \
    --vnet-name vnet \
    --subnet publicsubnet \
    --image UbuntuLTS \
    --admin-username azureuser \
    --no-wait \
    --custom-data cloud-init.txt \
    --admin-password <password>

###### reference
# https://github.com/MicrosoftDocs/
# AAD Topology https://docs.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-topologies
# https://github.com/Azure/azure-quickstart-templates
# https://resources.azure.com/

## create Machine with CLI
# https://docs.microsoft.com/en-us/learn/modules/improve-app-scalability-resiliency-with-load-balancer/4-exercise-configure-public-load-balancer?pivots=powershell
# https://github.com/MicrosoftDocs/mslearn-improve-app-scalability-resiliency-with-load-balancer
git clone https://github.com/MicrosoftDocs/mslearn-improve-app-scalability-resiliency-with-load-balancer.git
cd mslearn-improve-app-scalability-resiliency-with-load-balancer
bash create-high-availability-vm-with-sets.sh learn-9a77d185-cc22-4daf-b0fd-1b826093d148

# add MFA Method
Install-module Microsoft.Graph.Identity.Signins
Connect-MgGraph -Scopes UserAuthenticationMethod.ReadWrite.All
Select-MgProfile -Name beta
Get-MgUserAuthenticationPhoneMethod -UserId mygu@omygu.com
Get-MgUserAuthenticationPhoneMethod -UserId mygu@outlook.com

# invite guest for Azure AD
# URL: https://account.activedirectory.windowsazure.com/?tenantid=72f988bf-86f1-41af-91ab-2d7cd011db47&login_hint=mg@omygu.com

# Export template and convert to bicep
Export-AzResourceGroup -ResourceGroupName "your_resource_group_name" -Path ./main.json
bicep decompile main.json