 function New-SDNPrivateVIP
{
    param(

    [Parameter(Mandatory=$false)]
    # Name of the Network Controller Network Service
    # This value should be the name you gave the Network Controller service
    # when you on-boarded the Network Controller to VMM
    $LBServiceName = "Microsoft SDN Service",

    [Parameter(Mandatory=$false)]
    # Name of the workload VMs you want to load balance.
    $VipMemberVMNames =  @("vpc02-sub200-v1","vpc02-sub200-v2"),

    [Parameter(Mandatory=$false)]
    # Name of the VIP VM Network
    $VipNetworkName = "VPC02-vNet-01",

    [Parameter(Mandatory=$false)]
    # VIP address you want to assign from the VIP VM Network IP pool.
    # Pick any VIP that falls within your VIP IP Pool range.
    $VipAddress = "10.101.33.102",

    [Parameter(Mandatory=$false)]
    # The name of the VIP template you created via the VMM Console.
    $VipTemplateName = "SLB_HTTP80",

    [Parameter(Mandatory=$false)]
    # Arbitrary but good to match the VIP you're using.
    $VipName = "scvmm_10_101_33_102_80"

    )

    Import-Module virtualmachinemanager

    $lb = Get-scLoadBalancer | where { $_.Service.Name -like $LBServiceName};
    $vipNetwork = get-scvmnetwork -Name $VipNetworkName;

    $vipMemberNics = @();
    foreach ($vmName in $VipMemberVMNames)
    {
    $vm = get-scvirtualmachine -Name $vmName;
    #    if ($vm.VirtualNetworkAdapters[0].VMNetwork.ID -ne $vipNetwork.ID)
    #    {
    #        $vm.VirtualNetworkAdapters[0] | set-scvirtualnetworkadapter -VMNetwork $vipNetwork;
    #    }

    $vipMemberNics += $vm.VirtualNetworkAdapters[0];
    }

    $existingVip = get-scloadbalancervip -Name $VipName
    if ($existingVip -ne $null)
    {
    #    foreach ($mem in $existingVip.VipMembers)
    #    {
    #        $mem | remove-scloadbalancervipmember;
    #    }

    $existingVip | remove-scloadbalancervip;
    }

    $vipt = get-scloadbalancerviptemplate -Name $VipTemplateName;

    $vip = New-SCLoadBalancerVIP -Name $VipName -LoadBalancer $lb `
    -IPAddress $VipAddress -LoadBalancerVIPTemplate $vipt `
    -FrontEndVMNetwork $vipNetwork `
    -BackEndVirtualNetworkAdapters $vipMemberNics;
    Write-Output "Created VIP " $vip;

    $vip = get-scloadbalancervip -Name $VipName;
    Write-Output " VIP created successfully " $vip;
}


New-SDNPrivateVIP -LBServiceName "Microsoft SDN Service" `
                  -VipMemberVMNames @("vpc02-sub200-v1","vpc02-sub200-v2") `
                  -VipNetworkName "Network-HCI-PublicVIP" `
                  -VipAddress "172.17.97.15" `
                  -VipTemplateName "SLB_HTTP80" `
                  -VipName "scvmm_172_17_97_5_80"

#########
Get-SCStaticIPAddressPool | Select Name, NetworkSite, Subnet, AddressRangeStart, AddressRangeEnd, LogicalNetwork, VMHostGroups | ft 
Get-SCLoadBalancerVIP 
