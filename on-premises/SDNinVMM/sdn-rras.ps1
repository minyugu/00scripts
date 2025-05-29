 
Add-BgpRouter -BgpIdentifier 10.101.0.1 -LocalASN 65000

Get-BgpRouter | Remove-BgpRouter

Add-BgpPeer -Name muxvm001 -LocalIPAddress 10.101.0.1 -PeerIPAddress 10.101.0.16 `
            -LocalASN 65000 -PeerASN 65001 -OperationMode Mixed -PeeringMode Automatic

Add-BgpPeer -Name muxvm002 -LocalIPAddress 10.101.0.1 -PeerIPAddress 10.101.0.18 `
            -LocalASN 65000 -PeerASN 65002 -OperationMode Mixed -PeeringMode Automatic
            
Add-BgpPeer -Name muxvm003 -LocalIPAddress 10.101.0.1 -PeerIPAddress 10.101.0.17 `
            -LocalASN 65000 -PeerASN 65003 -OperationMode Mixed -PeeringMode Automatic

Get-BgpPeer | foreach {$_ | Remove-BgpPeer}

Get-BgpRouteInformation
Get-BgpRoutingPolicy 