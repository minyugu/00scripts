# Copyright (C) Microsoft Corporation.  All rights reserved.

function Get-NetworkControllerVipResourceMG
{
[CmdletBinding()]
    param(
        [String][parameter(Mandatory=$false, HelpMessage="The URI to be used for Network Controller REST APIs. Specify in case of wild card certificate deployment.")]$RestURI = $null,
        [String][parameter(Mandatory=$false, HelpMessage="Certificate thumbprint to use for Network Controller. Specify in case of certificate deployment.")]$CertificateThumbprint = $null,
        [System.Management.Automation.PSCredential][parameter(Mandatory=$false, HelpMessage="Credential to use for Network Controller. Specify in case of Kerberos deployment.")]$Credential = $null,
        [String][parameter(Mandatory=$false, HelpMessage="Direction of traffic flow")][ValidateSet("Out", "In")]$Direction = "In",
        [String][parameter(Mandatory=$true, HelpMessage="Destination IP Address")]$IPAddress,
        [String][parameter(Mandatory=$false, HelpMessage="Destination Port")]$DstPort,
        [String][parameter(Mandatory=$false, HelpMessage="Protocol")][ValidateSet("Tcp", "Udp", "All")]$Protocol
    )

    $vipInfoEntry=@{}
    $vipInfoEntry.Add('Type', "")
    $vipInfoEntry.Add('ResourceRef', "")
    $vipInfoEntry.Add('RuleState', "")
    $vipInfoEntry.Add('RuleIdleTimeoutInMinutes', "")
    $vipInfoEntry.Add('BackendPort', "")
    $vipInfoEntry.Add('BackendResourceRef', "")
    $vipInfoEntry.Add('BackendPoolAdressResourceRef', "")

    if ($CertificateThumbprint.Length -gt 0)
    {
        $clientCert=$CertificateThumbprint
    }

    $publicIps = GetRESTOutput "$RestURI/networking/v1/PublicIpAddresses" $Credential $clientCert
    foreach ($publicIp in $publicIps.value)
    {
        if ($IPAddress -ieq $publicIp.properties.ipAddress)
        {
            $PublicIPRef=$publicIp.resourceRef
            break
        }
    }

    if ($PublicIPRef -ne $null)
    {
        $nwIntfs = GetRESTOutput "$RestURI/networking/v1/NetworkInterfaces" $Credential $clientCert
        foreach ($nwIntf in $nwIntfs.value)
        {
            foreach ($nwIfConfig in $nwIntf.properties.ipConfigurations)
            {
                if ($PublicIPRef -eq $nwIfConfig.properties.publicIPAddress.resourceRef)
                {
                    # L3 NAT case
                    $vipInfoEntry.Type = "L3Nat"
                    $vipInfoEntry.ResourceRef = $nwIntf.resourceRef
                    $vipInfoEntry.RuleState = $null
                    $vipInfoEntry.RuleIdleTimeoutInMinutes = $null
                    $vipInfoEntry.BackendPort = $null
                    $vipInfoEntry.BackendResourceRef = $null
                    $vipInfoEntry.BackendPoolAdressResourceRef = $null
                    return $vipInfoEntry
                }
            }
        }
    }

    $lbs = GetRESTOutput "$RestURI/networking/v1/LoadBalancers" $Credential $clientCert
    $count=0
    foreach ($lb in $lbs.value)
    {

#MG Debug
#        if($lb.resourceId -eq "0c0991f0-b570-4668-9e5d-9e2db9810160") { Write-Host "pause" }

        foreach ($feIPConfig in $lb.properties.frontendIPConfigurations)
        {
            if ($PublicIPRef -ne $null)
            {
                if ($PublicIPRef -ieq $feIPConfig.properties.publicIpAddress.resourceRef)
                {
                    $feResource=$feIPConfig.resourceRef
                    $matchLb=$count
                    break
                }
            }
            else
            {
                if ($IPAddress -ieq $feIPConfig.properties.privateIPAddress)
                {
                    $feResource=$feIPConfig.resourceRef
                    $matchLb=$count
                    break
                }
            }
        }

        if ($matchLb -ne $null)
        {
            break
        }
        $count++
    }

    if ($matchLb -ne $null)
    {
        if ($Direction -ieq "In")
        {
            foreach ($lbRule in $lbs.value[$matchLb].properties.loadBalancingRules)
            {
                if ($DstPort -ieq $lbRule.properties.frontendPort -and (($Protocol -ieq $lbRule.properties.Protocol) -or ("All" -ieq $lbRule.properties.Protocol)))
                {
                    foreach ($feIPConfig in $lbRule.properties.frontendIPConfigurations)
                    {
                        if ($feIPConfig.resourceRef -ieq $feResource)
                        {
                            $lbRuleToFind=$lbRule.resourceRef
                            $lbRuleType="LoadBalancingRule"
                            $lbRuleState=$lbRule.properties.provisioningState
                            $lbRuleIdleTimeout=$lbRule.properties.idleTimeoutInMinutes
                            $lbBackendPort=[String]($lbRule.properties.backendPort)
                            $lbBackendResourceRef=$lbRule.properties.backendIPConfiguration.resourceRef
                            # backendIPConfiguration not exist, instead of get backendAddressPool
                            if ($lbBackendResourceRef -eq $nul)
                            {
                                $lbBackendPoolResourceRef=$lbRule.properties.backendAddressPool.resourceRef

                                # try to get IP Config in Backend Address Pools
                                if ($lbBackendPoolResourceRef -ne $null)
                                {
                                    foreach ($lbBackend in $lbs.value[$matchLb].properties.backendAddressPools)
                                    {
                                        if ($lbBackendPoolResourceRef -ieq $lbBackend.resourceRef)
                                        {
                                            $IPConfigInBackendPool = $lbBackend.properties.backendIPConfigurations.resourceRef
                                            if ($IPConfigInBackendPool -ne $null)
                                            {
                                                $lbBackendResourceRef = $IPConfigInBackendPool
                                            }

                                            break
                                        }
        
                                    }
                                }
                            }

                            break
                        }
                    }
                }
            }

            foreach ($lbRule in $lbs.value[$matchLb].properties.inboundNatRules)
            {
                if ($DstPort -ieq $lbRule.properties.frontendPort -and (($Protocol -ieq $lbRule.properties.Protocol) -or ("All" -ieq $lbRule.properties.Protocol)))
                {
                    foreach ($feIPConfig in $lbRule.properties.frontendIPConfigurations)
                    {
                        if ($feIPConfig.resourceRef -ieq $feResource)
                        {
                            $lbRuleToFind=$lbRule.resourceRef
                            $lbRuleType="InboundNatRule"
                            $lbRuleState=$lbRule.properties.provisioningState
                            $lbRuleIdleTimeout=$lbRule.properties.idleTimeoutInMinutes
                            $lbBackendPort=[String]($lbRule.properties.backendPort)
                            $lbBackendResourceRef=$lbRule.properties.backendIPConfiguration.resourceRef
                            # backendIPConfiguration not exist, instead of get backendAddressPool
                            if (!$lbBackendResourceRef)
                            {
                                $lbBackendResourceRef=$lbRule.properties.backendAddressPool.resourceRef
                            }
                            
                            break
                        }
                    }
                }
            }
        }
        else
        {
            foreach ($lbRule in $lbs.value[$matchLb].properties.outboundNatRules)
            {
                if (($Protocol -ieq $lbRule.properties.Protocol) -or ("All" -ieq $lbRule.properties.Protocol))
                {
                    foreach ($feIPConfig in $lbRule.properties.frontendIPConfigurations)
                    {
                        if ($feIPConfig.resourceRef -ieq $feResource)
                        {
                            $lbRuleToFind=$lbRule.resourceRef
                            $lbRuleType="OutboundNatRule"
                            $lbRuleState=$lbRule.properties.provisioningState
                            $lbRuleIdleTimeout=$lbRule.properties.idleTimeoutInMinutes
                            $lbBackendPort=$null
                            $lbBackendResourceRef=$lbRule.properties.backendIPConfiguration.resourceRef
                            # backendIPConfiguration not exist, instead of get backendAddressPool
                            if (!$lbBackendResourceRef)
                            {
                                $lbBackendResourceRef=$lbRule.properties.backendAddressPool.resourceRef
                            }
                            break
                        }
                    }
                }
            }
        }
    }

    $vipInfoEntry.Type = $lbRuleType
    $vipInfoEntry.ResourceRef = $lbRuleToFind
    $vipInfoEntry.RuleState = $lbRuleState
    $vipInfoEntry.RuleIdleTimeoutInMinutes = $lbRuleIdleTimeout
    $vipInfoEntry.BackendPort = $lbBackendPort
    $vipInfoEntry.BackendResourceRef = $lbBackendResourceRef
    $vipInfoEntry.BackendPoolAdressResourceRef = $lbBackendPoolResourceRef

    return $vipInfoEntry
}

function Get-VipHostMappingMG
{
   [CmdletBinding()]
    param(
        [string][parameter(Mandatory=$true, HelpMessage="One Network controller Node Name/IP")]$NetworkController,
        [System.Management.Automation.PSCredential][parameter(Mandatory=$false, HelpMessage="Credential to use for Network Controller. Specify in case of Kerberos deployment.")]$Credential = $null,
        [String][parameter(Mandatory=$true, HelpMessage="The URI to be used for Network Controller REST APIs. Specify in case of wild card certificate deployment.")]$RestURI = $null,
        [String][parameter(Mandatory=$false, HelpMessage="Certificate thumbprint to use for Network Controller. Specify in case of certificate deployment.")]$CertificateThumbprint = $null,
        [String][parameter(Mandatory=$true, HelpMessage="VipEndpoint Resource Reference")]$VipEndPoint,
        [String][parameter(Mandatory=$true, HelpMessage="Type of VipEndPoint")][ValidateSet("L3Nat","InboundNatRule","LoadBalancingRule", "OutboundNatRule")]$Type
    )

    # get muxes connected to NC.
    $virtualServers = GetRESTOutput "$RestURI/networking/v1/VirtualServers" $Credential $clientCert
    $vsDict=@{}
    foreach ($vs in $virtualServers.value)
    {
        $vsDict.Add($vs.resourceRef, $vs)
    }
    
    $muxs = GetRESTOutput "$RestURI/networking/v1/LoadBalancerMuxes" $Credential $clientCert
    [System.Collections.ArrayList]$muxVs=@()
    foreach ($mux in $muxs.value)
    {
        if ($vsDict.ContainsKey($mux.properties.virtualServer.resourceRef) -eq $true)
        {
            $muxVs.Add($vsDict[$mux.properties.virtualServer.resourceRef]) | Out-Null
        }
    }

    $muxs = GetAllManagementIPs $muxVs
    [System.Collections.ArrayList]$MuxList=@()
    $muxInfoEntry=@{}
    $muxInfoEntry.Add('Name', "")
    $muxInfoEntry.Add('Credentials', [System.Management.Automation.PSCredential]$null)
    foreach ($mux in $muxs)
    {
        $newmuxInfoEntry = $muxInfoEntry.Clone()
        $newmuxInfoEntry.Name=$mux
        $MuxList.Add($newmuxInfoEntry) | Out-Null
    }

    [System.Collections.ArrayList]$DIPInterfaceToHost=@()
    $entry=@{}
    $hostInfoEntry=@{}
    $hostInfoEntry.Add('Name', "")
    $hostInfoEntry.Add('Credentials', [System.Management.Automation.PSCredential]$null)
    $entry.Add('PortProfile', "")
    $entry.Add('HostInfo', $hostInfoEntry)
    

    # L3 NAT Case
    if ($Type -ieq "L3Nat")
    {
        $networkIntfInfo = GetRESTOutput "$RestURI/networking/v1$VipEndPoint" $Credential $clientCert
        $PortProfile='{'+$networkIntfInfo.InstanceId+'}'
        $networkIntfHost=$networkIntfInfo.properties.Server.resourceRef
        $serverInfo = GetRESTOutput "$RestURI/networking/v1$networkIntfHost" $Credential $clientCert
        $serverManagementIP=GetAllManagementIPs $serverInfo
        $newEntry=$entry.Clone()
        $newEntry.PortProfile=$PortProfile
        $newEntry.HostInfo.Name=$serverManagementIP
        $DIPInterfaceToHost.Add($newEntry) | Out-Null
    }
    else
    {    
        $VipInfo = GetRESTOutput "$RestURI/networking/v1$VipEndPoint" $Credential $clientCert
        if ($Type -ieq "LoadBalancingRule")
        {
            $vipbackendAddressPool=$vipInfo.properties.backendAddressPool.resourceRef
            $vipbackendAddressPoolInfo = GetRESTOutput "$RestURI/networking/v1$vipbackendAddressPool" $Credential $clientCert
            $ipConfigs = $vipbackendAddressPoolInfo.properties.backendIPConfigurations
        }
        elseif ($Type -ieq "OutboundNatRule")
        {
            $vipbackendAddressPool=$vipInfo.properties.backendAddressPool.resourceRef
            $vipbackendAddressPoolInfo = GetRESTOutput "$RestURI/networking/v1$vipbackendAddressPool" $Credential $clientCert
            $ipConfigs = $vipbackendAddressPoolInfo.properties.backendIPConfigurations
        }
        elseif ($Type -ieq "InboundNatRule")
        {
            $vipbackendIPConfig=$vipInfo.properties.backendIPConfiguration.resourceRef
            $ipConfigs = @{resourceRef = $vipbackendIPConfig}
        }

        foreach ($ipConfig in $ipConfigs)
        {
            $ipConfigTemp = $ipConfig.resourceRef.Split('/')
            $networkIntf = "/"+$ipConfigTemp[1]+"/"+$ipConfigTemp[2]

            $networkIntfInfo = GetRESTOutput "$RestURI/networking/v1$networkIntf" $Credential $clientCert
            $PortProfile='{'+$networkIntfInfo.InstanceId+'}'
            $networkIntfHost=$networkIntfInfo.properties.Server.resourceRef
            $serverInfo = GetRESTOutput "$RestURI/networking/v1$networkIntfHost" $Credential $clientCert
            $serverManagementIP=GetAllManagementIPs $serverInfo
            $newEntry=$entry.Clone()
            $newEntry.PortProfile=$PortProfile
            $newEntry.HostInfo.Name=$serverManagementIP
            $DIPInterfaceToHost.Add($newEntry) | Out-Null
        }
    }

    $output = @{}
    $output.Add("MuxList", $MuxList)
    $output.Add("DIPHosts", $DIPInterfaceToHost)

    return $output
}

#region Utility functions

function GetAllManagementIPs
{
    param($resources)

    $ips = @()

    foreach($resource in $resources)
    {
        $connections = $resource.properties.connections.Where{$_.managementAddresses -ne $null -and $_.managementAddresses.Count -gt 0}
        if($connections -ne $null -and $connections.Count -gt 0)
        {
            $connection = $connections.Where{$_.credentialType -eq 'UsernamePassword'}
            if($connection -eq $null -or $connection.Count -eq 0)
            {
                $connection = $connections[0]
            }
            else
            {
                $connection = $connection[0]
            }

            $managementIPAddress = $connection.managementAddresses[0]
            if(-not $ips.Contains($managementIPAddress))
            {
                $ips += $managementIPAddress
            }
        }
    }
    return $ips
}

function GetRESTOutput
{
    param($Url, $credential, $clientCert)

    if($clientCert -ne $null)
    {
        $restOutput = Invoke-RestMethod "$Url" -CertificateThumbprint $clientCert -UseBasicParsing
    }
    elseif($credential -ne $null)
    {
        $restOutput = Invoke-RestMethod "$Url" -Credential $credential -UseBasicParsing
    }
    else
    {
        $restOutput = Invoke-RestMethod "$Url" -UseBasicParsing -UseDefaultCredentials
    }

    return $restOutput
}

function InvokeREST
{
    param($BaseUrl, $BaseType, $OutputFolder, $Credential, $ClientCert, $ResourceId)

    $_baseType = $BaseType;
    if ($ResourceId -ne $nul)
    {
        $_baseType += "/$ResourceId"
    }

    $URL = "$BaseUrl/$_baseType"

    $restOutput = GetRESTOutput $URL $Credential $ClientCert

    $BaseTypePath=$BaseType.Replace('/', '-')
    $restOutput | ConvertTo-Json -Depth 10 >> "$OutputFolder/$BaseTypePath.Json"

    return $restOutput
}
#endregion

Export-ModuleMember -Function Get-NetworkControllerVipResourceMG
Export-ModuleMember -Function Get-VipHostMappingMG