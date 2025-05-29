# Prints a DIFF state (status is automatically updated if state is changed) of a particular service module replica
# nc
Debug-ServiceFabricNodeStatus [-ServiceTypeName] <Service Module>
$ncServices = @( "ControllerService"
                "ApiService"
                "SlbManagerService"
                "ServiceInsertion"
                "FirewallService"
                "VSwitchService"
                "GatewayManager"
                "FnmService"
                "HelperService"
                "UpdateService"
            )
$ncServices | foreach {Debug-ServiceFabricNodeStatus -ServiceTypeName $_}
Debug-ServiceFabricNodeStatus -ServiceTypeName $ncServices[4]
Debug-ServiceFabricNodeStatus -ServiceTypeName "VSwitchService"
Get-NetworkControllerReplica 

# mux
$uri = "https://nccluster.mshci.com"
$Muxs = @{
       '3DFDE937-4CE5-41B5-8C4D-05F06030F7A9' = "muxvm001";
       "AA4AF2F7-844A-45C4-964A-EE281CE9A576" = "muxvm003"
       "F58A10AE-BAC0-4BAF-BC69-3CEB23723354" = "muxvm002"
   }
$muxStatus = @()
(Get-NetworkControllerLoadBalancerMux -ConnectionUri $uri) | ForEach-Object {
    $muxStatus += [PSCustomObject]@{
        'SLB Name' = "$($Muxs[$_.ResourceId.replace('_suffix','')])"
        'SLB ResourceId' = $_.ResourceId
        Source = $_.Properties.ConfigurationState.DetailedInfo.source
        Message = $_.Properties.ConfigurationState.DetailedInfo.message
        Code = $_.Properties.ConfigurationState.DetailedInfo.code
    }
}
$muxStatus | FT 

((Get-NetworkControllerLoadBalancerMux -ConnectionUri $uri).Properties.ConfigurationState.DetailedInfo)
(Get-NetworkControllerLoadBalancer -ConnectionUri $uri).Properties
Get-NetworkControllerLoadBalancer -ConnectionUri $uri | ConvertTo-Json -Depth 4 


# host
netstat -anp tcp |findstr 6640
Get-ProviderAddress
Get-PACAMapping 
Get-Service SlbHostAgent
Get-Service NcHostAgent

# SLB 179
netstat -n
muxDriverControlConsole.exe /GetStatefulVip

# rras
Get-BgpRouter 
Get-BgpPeer 

