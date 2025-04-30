Function Write-Log{
    [CmdLetBinding()]
    Param(
        [String]$Message,
        [ValidateSet("Info","Warning","Error")]
        [String]$Type = "Info"
    )
    $FormattedDate = Get-Date -Format "yyyyMMdd-HH:mm:ss"
    $FormattedMessage = "[$FormattedDate] [$Type] $Message"
    $messageColor = "Green"
    Switch($Type)
    {
        "Info"{ $messageColor = "Green"}
        "Warning"{$messageColor = "Yellow"}
        "Error"{$messageColor = "Red"}
    }

    if($Type -eq "Info")
    {
        Write-Verbose $FormattedMessage
    }else {
        Write-Host -ForegroundColor $messageColor $FormattedMessage
    }

    #$formattedMessage | out-file "$OutputPath\SDNDiagnosticLog.txt" -Append
}

Function Get-SdnHostInvalidRootCertificate{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $SdnHost
    )
    return Invoke-Command -ComputerName $SdnHost -ScriptBlock{
        $output = @()

        $rootCAs = get-childitem "Cert:\localmachine\Root"
        $i = 0;

        foreach($rootCA in $rootCAs)
        {
            if (![System.String]::Equals($rootCA.Issuer, $rootCA.Subject, [System.StringComparison]::CurrentCultureIgnoreCase))
            {
                if ($rootCA.EnhancedKeyUsageList.Count -eq 0)
                {
                    continue;
                }

                if (![System.String]::IsNullOrEmpty($rootCA.FriendlyName))
                {
                    $output[$i] = $rootCA.FriendlyName;
                }
                else
                {
                    $nameparts = $rootCA.Subject.Split(",");

                    foreach($namePart in $nameparts)
                    {
                        if ($namepart.IndexOf("CN", [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
                        {
                            $cnPart = $namePart.Split("=");
                            $cn = $cnPart[1];
                        }

                    }

                    if (![System.String]::IsNullOrEmpty($cn))
                    {
                        $output[$i] = $cn;
                    }
                    else
                    {
                        $output[$i] = $rootCA.Subject;
                    }
                }
                $i = $i + 1;
            }
        }
        return $output
    }

}

Function Get-SdnHostVfpEnabledSwitches{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $SdnHost
    )

    Invoke-Command -ComputerName $SdnHost -ScriptBlock{
        $vmSwitches = Get-VMSwitch *
        $vfpEnabledSwitches = @()
        $vmSwitches | ForEach-Object{
            if((Get-VMSwitchExtension -Name "Microsoft Azure VFP Switch Extension" -VMSwitch $_).Enabled -eq $true)
            {
                $vfpEnabledSwitches += $_.Name
            }
        }
        return $vfpEnabledSwitches
    }
}

Function Get-RequiredModules()
{
    $feature = get-windowsfeature "RSAT-NetworkController" -Verbose:$false
    if (!$feature.Installed) {
        Write-Log "RSAT-NetworkController Not Installed"
        add-windowsfeature "RSAT-NetworkController" -Confirm
        $feature = get-windowsfeature "RSAT-NetworkController" -Verbose:$false
    }else
    {
        Write-Log "RSAT-NetworkController Installed"
    }
    return $feature.Installed
}

Function Get-SdnNcUri{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $NcVMName
    )
    $nc = Get-NetworkController -ComputerName $NcVMName
    $NcUri = "https://$($nc.RestName)"
    return $NcUri
}

Function Get-SdnNcRestName{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $NcVMName
    )
    $nc = Get-NetworkController -ComputerName $NcVMName
    return $nc.RestName
}

Function Get-SdnInfraNodes
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]$NcVMName,
        [String]$NcUri,
        [Parameter(Mandatory=$True)]
        [ValidateSet("Server","Gateway","Mux")]
        [String]$RoleType
    )

    if([String]::IsNullOrEmpty($NcUri))
    {
        if([String]::IsNullOrEmpty($NcVMName))
        {
            Write-Log "No NcUri or NcVMName specified" -Type Error
            return
        }else {
            $NcUri = Get-SdnNcUri $NcVMName
            Write-Log "Retreived NcUri $NcUri"

        }
    }

    $infraNodes = @()
    Write-Log "Looking for SDN Infra Nodes of type $RoleType"
    if($RoleType -eq "Mux")
    {
        $muxResources = Get-NetworkControllerLoadBalancerMux -ConnectionUri $NcUri
        foreach($muxResource in $muxResources)
        {
            $muxVirtualServerResourceId = $muxResource.properties.virtualserver.ResourceRef -replace "/VirtualServers/"
            $muxVirtualServerAddress = Get-SdnVirtualServerAddress -ResourceId $muxVirtualServerResourceId -NcUri $NcUri
            if($muxVirtualServerAddress -eq $null)
            {
                Write-Log "MUX $($muxResources.ResourceId) pointed to virtual server $muxVirtualServerResourceId have no management address found" -Type "Warning"
            }else
            {
                $infraNodes += $muxVirtualServerAddress
            }
        }
    }elseif($RoleType -eq "Gateway")
    {
        $gwResources = Get-NetworkControllerGateway -ConnectionUri $NcUri
        foreach($gwResource in $gwResources)
        {
            $gwVirtualServerResourceId = $gwResource.properties.virtualserver.ResourceRef -replace "/VirtualServers/"
            $gwVirtualServerAddress = Get-SdnVirtualServerAddress -ResourceId $gwVirtualServerResourceId -NcUri $NcUri
            if($gwVirtualServerAddress -eq $null)
            {
                Write-Log "Gateway $($muxResources.ResourceId) pointed to virtual server $gwVirtualServerResourceId have no management address found" -Type "Warning"
            }else
            {
                $infraNodes += $gwVirtualServerAddress
            }
        }
    }elseif($RoleType -eq "Server")
    {
        $serverResources = Get-NetworkControllerServer -ConnectionUri $NcUri
        foreach($serverResource in $serverResources)
        {
            $managementAddress = $serverResource.Properties.Connections[0].ManagementAddresses[0]
            $infraNodes += $managementAddress
        }
    }
    return $infraNodes
}

Function Get-SdnHostInfo
{
    [CmdletBinding()]
    param (
        # The NCURI
        [Parameter(Mandatory=$True)]
        [String]
        $NcUri,
        [string]
        $ResourceId = '',
        [String]
        $ResourceRef = ''
    )

    $serverResources = @()
    if([String]::IsNullOrEmpty($ResourceId) -and ![String]::IsNullOrEmpty($ResourceRef))
    {
        if($ResourceRef -match 'servers/([\w\-]+)')
        {
            $ResourceId = $matches[1]
        }
    }

    if(![String]::IsNullOrEmpty($ResourceId))
    {
        $serverResources = Get-NetworkControllerServer -ConnectionUri $NcUri -ResourceId $ResourceId
    }else
    {
        $serverResources = Get-NetworkControllerServer -ConnectionUri $NcUri
    }

    $serverInfoArray = @()
    foreach($serverResource in $serverResources)
    {
        $serverInfo = [PSCustomObject]@{
            ResourceId = $serverResource.ResourceId
            InstanceId = $serverResource.InstanceId
            ResourceState = $serverResource.Properties.ProvisioningState
            ManagementAddress = $serverResource.Properties.Connections[0].ManagementAddresses[0]
        }

        $serverInfoArray + $serverInfo
    }


    return $serverInfoArray
}

Function Get-SdnHostNcHaRegistryInfo{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $SdnHost
    )

    return Invoke-Command -ComputerName $SdnHost -ScriptBlock{

        $NcHaParameters = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters'

        $NcHaRegInfo = [PSCustomObject]@{
            Connections = $NcHaParameters.Connections
            PeerCertificateCName = $NcHaParameters.PeerCertificateCName
            HostAgentCertificateCName = $NcHaParameters.HostAgentCertificateCName
            HostId = $NcHaParameters.HostId
        }
        return $NcHaRegInfo
    }
}

function Set-TrustedHosts
{
    param ($value)
    Set-Item WSMan:\\localhost\\Client\\TrustedHosts $value -Force
}
function Set-TrustedHostsToAll
{
    Set-TrustedHosts *
    Write-Log "Completed Set-TrustedHosts"
}

function Get-TrustedHosts
{
    return (Get-Item WSMan:\\localhost\\Client\\TrustedHosts).Value
}


function Get-SdnResources
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $NcUri,
        [String]
        $OutputPath = "."
    )

    $OutputPath = "$OutputPath\SDNResources"
    # Gather Network Controller resources
    Write-Log -Message "Gathering SDN configuration details. Results saved to $OutputPath"
    New-Item -Path "$OutputPath" -ItemType Directory -Force | Out-Null
    [array]$SDNResources="AccessControlLists","Credentials","GatewayPools","Gateways","LoadBalancerMuxes","LoadBalancers","LogicalNetworks","MacPools","NetworkInterfaces","PublicIPAddresses","Servers","RouteTables","VirtualGateways","VirtualNetworks","VirtualServers","iDNSServer/configuration","LoadBalancerManager/config","virtualNetworkManager/configuration","serviceInsertions"
    foreach ($resource in $SDNResources){
        Try {
            Invoke-RestMethod -Uri "$NcUri/networking/v1/$resource" -Method Get -UseDefaultCredentials -Verbose:$false | ConvertTo-Json -Depth 100 | Out-File "$OutputPath\$resource.json".Replace("/","_")
        }
        Catch {
            if($_.Exception.Response.StatusCode.Value__ -ne 404)
            {
                Write-Log -Message "$($_.Exception)
                at $($_.Exception.Response.ResponseUri.AbsoluteUri)" -Type "Error"
            }else
            {
                Write-Log "$resource not found" -Type "Warning"
            }
        }
    }
}

Function Start-NCImosDump
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $NcUri
    )

	Import-Module NetworkController -Verbose:$false

	Write-Log "Triggering IMOS Dump"
	$state=New-Object Microsoft.Windows.NetworkController.NetworkControllerStateProperties
	$ncStateResult = Invoke-NetworkControllerState -ConnectionUri $NCUri -Properties $state -Force

    $ncState = Invoke-RestMethod -Uri "$($NCUri)/networking/v1/diagnostics/networkcontrollerstate" -UseDefaultCredentials -Verbose:$false
    $timeout = 300
    Write-Log "Waiting for IMOS Dump finish"
	while($timeout -gt 0)
	{
		$ncState = Invoke-RestMethod -Uri "$($NCUri)/networking/v1/diagnostics/networkcontrollerstate" -UseDefaultCredentials -Verbose:$false
		if($ncState.properties.provisioningState -ne "Updating")
		{
			break
		}
		Start-Sleep -s 10
		$timeout = $timeout - 10
	}
	Write-Log "IMOS Dump finished status: $($ncState.properties.provisioningState)"
}

Function Get-SdnNcImosDump
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='NcUri')]
        [String[]]
        $NcVMs,
        [Parameter(Mandatory=$true, ParameterSetName='NcUri')]
        [String]
        $NcUri,
        [Parameter(Mandatory=$true, ParameterSetName='NcVM')]
        [String]
        $NcVMName,
        [String]
        $OutputPath = "."
    )

    if(![String]::IsNullOrEmpty($NcVMName))
    {
        $SdnInfraInfo = Get-SdnInfraInfo -NcVMName $NcVMName
        $NcVMs = $SdnInfraInfo.NC
        $NcUri = $SdnInfraInfo.NcUri
    }
    Write-Log "Getting IMOS Dump via NCURI: $NcUri"
    # Cleanup the existing IMOS Dump folder to generate a new one

    Invoke-Command -ComputerName $NcVMs -ScriptBlock{
        Write-Verbose "[$(HostName)] Cleaning IMOS DB folder"
        Get-ChildItem -Path "C:\Windows\tracing\SDNDiagnostics\NetworkControllerState" | Remove-Item -Force
    }

    Start-NCImosDump -NCUri $NcUri

    foreach($NcVM in $NcVMs)
    {
        Write-Log "Getting IMOS dump from $($NcVM)"
        $RemotePathToCopy = "\\$($NcVM)\c$\Windows\Tracing\SDNDiagnostics\NetworkControllerState\*"
        New-Item "$OutputPath\NetworkControllerState" -ItemType Directory -Force | Out-Null
        Write-Log "Copying from $RemotePathToCopy to $OutputPath\NetworkControllerState"
       	Copy-Item -Path $RemotePathToCopy -Destination "$OutputPath\NetworkControllerState" -Recurse
    }
}

Function Get-SdnSlbDiagnosticState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $NcUri
    )

    $requestBody = '{"properties": { }}'
    $resultObject = Invoke-RestMethod -Uri "$NcUri/Networking/v1/diagnostics/slbstate"  -UseDefaultCredentials -Verbose:$false -Method Put -Body $requestBody -ContentType "application/json; charset=UTF-8"
    $resultsUri = "$NcUri/Networking/v1$($resultObject.properties.slbStateResult.resourceRef)"

    $slbStateRetry = 10
    $maxRetryCount = 20

    do
    {
      $totalWait += $slbStateRetry
      Write-Log ">>> Sleeping ... for $slbStateRetry seconds ..."
      Start-Sleep -Seconds $slbStateRetry
      Write-Log ">>> Polling ... $resultsUri"
      $tempResult = Invoke-RestMethod -Headers $headers -Method GET -Uri $resultsUri -UseBasicParsing -UseDefaultCredentials
      Write-Log ">>> Current State: $($tempResultObject.properties.provisioningState)"
    }
    until (($tempResult.properties.provisioningState) -ne "Updating" -or $totalWait -gt $slbStateRetry * $maxRetryCount)
    return $tempResult.properties.output
}

Function Get-NCLogInMin
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $NCVMName,
        [int]
        $LastInMin,
        [String]
        $OutputPath
    )

    $LatestTime = (Get-Date).AddMinutes(-$latestTimeInMins)
    $LatestTime = $LatestTime.ToUniversalTime()

    $NCVMs = Get-NetworkControllerNode -ComputerName $NCVMName
    foreach($NCVM in $NCVMs)
    {
        Write-Log "Getting NC ETL logs from $($NCVM.Server)"

        $ToCopy = Invoke-Command -ComputerName $($NCVM.Server) -ArgumentList $LatestTime -ScriptBlock{
        Param(
            [DateTime]$LatestTime
        )
            $logs = Get-ChildItem -Path "C:\Windows\Tracing\*.log"
            $etls = Get-ChildItem -Path "C:\Windows\Tracing\SDNDiagnostics\Logs" | sort LastWriteTime -Descending
            $EtlToCopy = @()
            foreach($etl in $etls)
            {
                $EtlToCopy += $etl.Name
                if($etl.LastWriteTimeUtc -le $LatestTime)
                {
                    return $EtlToCopy
                }

            }
        }

        Write-Log "Invoke-Command done for $($NCVM.Server)"
        $RemotePathToCopy = "\\$($NCVM.Server)\c$\Windows\Tracing\SDNDiagnostics\Logs\"


        $NCVMFolder = New-Item -ItemType Directory  -Path "$OutputPath\$($NCVM.Server)\ETL"
        foreach($Etl in $ToCopy)
        {
            Copy-Item -Path $RemotePathToCopy\$Etl -Destination "$($NCVMFolder.FullName)\$Etl"
        }
    }
}


Function Get-NCLogInNumber
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $NCVMName,
        [int]
        $LastInNum,
        [String]
        $OutputPath
    )

    $NCVMs = Get-NetworkControllerNode -ComputerName $NCVMName
    foreach($NCVM in $NCVMs)
    {
        Write-Log "Getting logs from $($NCVM.Server)"

        $ToCopy = Invoke-Command -ComputerName $($NCVM.Server) -ArgumentList $LastInNum -ScriptBlock{
        Param(
            [int]$LastInNum
        )
            $logs = Get-ChildItem -Path "C:\Windows\Tracing\*.log"
            $etls = Get-ChildItem -Path "C:\Windows\Tracing\SDNDiagnostics\Logs" -Filter "*ETL*" | sort LastWriteTime -Descending
            $EtlToCopy = @()
            foreach($etl in $etls)
            {
                $EtlToCopy += $etl.Name
                if($LastInNum -gt 0){
                    $LastInNum --
                }
                if($LastInNum -eq 0)
                {
                    return $EtlToCopy
                }

            }

            return $EtlToCopy
        }

        Write-Log "Invoke-Command done for $($NCVM.Server)"
        $RemotePathToCopy = "\\$($NCVM.Server)\c$\Windows\Tracing\SDNDiagnostics\Logs\"


        $NCVMFolder = New-Item -ItemType Directory  -Path "$OutputPath\$($NCVM.Server)\ETL"
        foreach($Etl in $ToCopy)
        {
            Copy-Item -Path $RemotePathToCopy\$Etl -Destination "$($NCVMFolder.FullName)\$Etl"
        }
    }
}

Function Get-SdnNcClusterInfo
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $NCVMName,
        [String]
        $OutputPath
    )

    Write-Log "Getting NC Cluster Info"
    New-Item -Path "$OutputPath\NCClusterInfo" -ItemType Directory -Force | Out-Null
    $OutputPath = "$OutputPath\NCClusterInfo"
    $ncPSSession = New-PSSession -ComputerName $NCVMName
    Invoke-Command -Session $ncPSSession -ScriptBlock{
        Get-NetworkControllerReplica
    }| Out-File -FilePath "$OutputPath\GetNetworkControllerReplica.txt"

    Invoke-Command -Session $ncPSSession -ScriptBlock{
        Get-NetworkController
    } | Out-File -FilePath "$OutputPath\GetNetworkController.txt"

    Invoke-Command -Session $ncPSSession -ScriptBlock{
        Get-NetworkControllerNode
    } | Out-File -FilePath "$OutputPath\GetNetworkControllerNode.txt"


    $sfClusterInfo = Invoke-Command -Session $ncPSSession -ScriptBlock{
        Connect-ServiceFabricCluster | Out-Null
        Get-ServiceFabricClusterHealth | Select-Object AggregatedHealthState, NodeHealthStates, ApplicationHealthStates | ft -AutoSize
        Get-ServiceFabricNode | Format-Table NodeName, IpAddressOrFQDN, NodeStatus, NodeUpTime, HealthState, ConfigVersion, CodeVersiom, FaultDomain, UpgradeDomain -AutoSize | Out-String -Width 4096
        Get-ServiceFabricApplication -ApplicationName fabric:/NetworkController | ft ApplicationName, ApplicationStatus, HealthState -AutoSize
        Get-ServiceFabricService -ApplicationName fabric:/NetworkController | ft ServiceName, ServiceStatus, HealthState -AutoSize
        Get-ServiceFabricService -ApplicationName fabric:/System | ft ServiceName, ServiceStatus, HealthState -AutoSize
    }

    $sfClusterInfo | Out-File -FilePath "$OutputPath\ServiceFabricHealth.txt"

}
Function Start-SdnHostTrace
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String[]]
        $SdnHosts,
        [Switch]
        $IncludeVfp
    )

    if($SdnHosts.Count -gt 0){
        Invoke-Command -ComputerName $SdnHosts -ScriptBlock{
            Param(
                [bool]$IncludeVfp
            )

            $TraceDir = "C:\Temp\CSS_SDN\Traces"

            # Stop the trace if that is running
            $sessionNames = @("ncha", "vm_dv", "slbha", "vfp")
            $allEtwSessions = Get-EtwTraceSession *
            foreach($sessionName in $sessionNames)
            {
                $etwSession = $allEtwSessions | where name -eq $sessionName
                if($null -ne $etwSession)
                {
                    Write-Host "[$(HostName)] Existing trace session $sessionName found, stop it"
                    $etwSession | Stop-EtwTraceSession
                    if($sessionName -eq "vfp")
                    {
                        # If vfp trace session found, also stop netsh trace
                        netsh trace stop
                    }
                }
            }

            # Cleanup the traces folder before start new trace
            if(Test-Path $TraceDir){
                Write-Host "[$(HostName)] Log path $TraceDir existed, remove the old logs and recreate"
                Remove-Item "$TraceDir\*" -Recurse -Force
            }else
            {
                New-item -Path $TraceDir -ItemType Directory -Force
            }

            logman create trace "ncha" -ow -o "$TraceDir\ncha.etl" -p "{28F7FB0F-EAB3-4960-9693-9289CA768DEA}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
            logman update trace "ncha" -p "{A6527853-5B2B-46E5-9D77-A4486E012E73}" 0xffffffffffffffff 0xff -ets
            logman update trace "ncha" -p "{dbc217a8-018f-4d8e-a849-acea31bc93f9}" 0xffffffffffffffff 0xff -ets
            logman update trace "ncha" -p "{41DC7652-AAF6-4428-BBBB-CFBDA322F9F3}" 0xffffffffffffffff 0xff -ets
            logman update trace "ncha" -p "{F2605199-8A9B-4EBD-B593-72F32DEEC058}" 0xffffffffffffffff 0xff -ets

            logman create trace "vm_dv" -ow -o "$TraceDir\m_dv.etl" -p "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
            logman update trace "vm_dv" -p "{6C28C7E5-331B-4437-9C69-5352A2F7F296}" 0xffffffffffffffff 0xff -ets

            logman create trace "slbha" -ow -o "$TraceDir\slbha.etl" -p "{2380c5ee-ab89-4d14-b2e6-142200cb703c}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets


            if($IncludeVfp){
                #Start the VFP related trace

                logman create trace "vfp" -ow -o "$TraceDir\vfpext.etl" -p "{9F2660EA-CFE7-428F-9850-AECA612619B0}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
                logman update trace "vfp" -p "Microsoft-Windows-Hyper-V-Vmswitch" 0xffffffffffffffff 0xff -ets
                logman update trace "vfp" -p "Microsoft-Windows-NDIS-PacketCapture" 0xffffffffffffffff 0xff -ets

                netsh trace start capture=yes overwrite=yes maxsize=2048 tracefile="$TraceDir\host_nettrace.etl" scenario=virtualization capturetype=both
            }
            Write-Host "Started SDN Host Trace at $(HostName)"
        } -ArgumentList $IncludeVfp
    }else {
        Write-Error "No SDN Hosts Specified"
        return
    }
}

Function Stop-SdnHostTrace
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String[]]
        $SdnHosts,
        [Switch]
        $IncludeVfp,
        [String]
        $OutputPath
    )

    if($SdnHosts.Count -gt 0){
        Invoke-Command -ComputerName $SdnHosts -ScriptBlock{
            param(
                [bool]$IncludeVfp
            )
            Write-Host "[$(HostName)] Stopping SDN Host Trace"
            logman stop "ncha" -ets
            logman stop "vm_dv" -ets
            logman stop "slbha" -ets

            if($IncludeVfp){
                #Stop VFP related trace
                logman stop "vfp" -ets
                netsh trace stop
            }
        } -ArgumentList $IncludeVfp
    }else
    {
        Write-Error "No SDN Hosts Specified"
        return
    }
}

# Function to collect logs from Infra Nodes. This used to collect static logs only
Function Get-SdnInfraNodeLogs{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $InfraNodes,
        [Parameter(Mandatory = $true)]
        [ValidateSet("NC","MUX","GW","HyperV")]
        [String]
        $Role,
        [String]
        $OutputPath,
        [DateTime]
        $FromDate = (Get-Date).AddHours(-4),
        [DateTime]
        $ToDate
    )

    $OutputPath = Get-OutputPath $OutputPath
    $DataCollectionDir = "C:\Temp\CSS_SDN"
    $InfraNodeSessions = @()

    Write-Log -Message "Creating remote sessions to Infra Nodes: $InfraNodes"
    Write-Log -Message "Collecting logs between [$FromDate] and [$ToDate]"
    foreach ($InfraNode in $InfraNodes){
        Try {
            $InfraNodeSessions += New-PSSession -ComputerName $InfraNode -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "$_" -Type Error
            continue
        }
    }

    # Gather data from data nodes
    Write-Log -Message "Gathering $Role Logs from $($InfraNodeSessions.ComputerName)"
    $InvokeRemoteJob = Invoke-Command -Session $InfraNodeSessions -ScriptBlock {
        Param(
            [String] $Role,
            [String] $DataCollectionDir
        )
        function Write-Log(
            [String]$Message,
            [ValidateSet("Info","Warning","Error")]
            [String]$Type = "Info")
        {
            $FormattedDate = date -Format "yyyyMMdd-HH:mm:ss"
            $FormattedMessage = "[$FormattedDate] [$Type] [$(HostName)] $Message"
            $messageColor = "Green"
            Switch($Type)
            {
                "Info"{ $messageColor = "Green"}
                "Warning"{$messageColor = "Yellow"}
                "Error"{$messageColor = "Red"}
            }
            if($Type -eq "Info")
            {
                Write-Verbose $FormattedMessage
            }else {
                Write-Host -ForegroundColor $messageColor $FormattedMessage
            }

            $formattedMessage | out-file "$DataCollectionDir\SDNLogCollectLog.txt" -Append
        }
        New-Item -Path "$DataCollectionDir\SDNLogCollectLog.txt" -Force
        # Remove the temp local directory if existed to cleanup old
        if(Test-Path $DataCollectionDir){
            Write-Log "Log path $DataCollectionDir existed, remove the old logs and recreate"
            # Exclude folder "Traces" that include the dynamically started traces leave the cleanup to stop trace call
            Get-ChildItem $DataCollectionDir -Exclude "Traces" | Remove-Item -Recurse -Force
        }

        Write-Log "Creating Folder $DataCollectionDir"
        # Create local directory now
        New-Item -Path "$DataCollectionDir" -ItemType Directory -Force | Out-Null
        New-Item -Path "$DataCollectionDir\SDNLogCollectLog.txt" -Force

        Write-Log "Started Data Collection"

        Write-Progress -Activity "[$(HostName)] Log collection" -Status "Copying general logs for all role" -PercentComplete 10
        # Collect general logs for any role
        $folders = Get-ChildItem -Path "C:\Windows\Tracing" -Recurse -Directory | Where-Object {$_.Name -ne "NetworkControllerState" -and $_.Name -ne "CrashDumps" -and $_.name -ne "AutoBackups"}
        $folders += Get-Item -Path "C:\Windows\Tracing"

        # Gather trace files that generated within FromDate (by default 4 hours) and ToDate specified  from defined folders
        foreach ($folder in $folders){
            $logfiles = Get-ChildItem -Path $folder.FullName | Where-Object {$_.LastWriteTime -ge $using:FromDate -and $_.Attributes -ne "Directory"}
            foreach ($file in $logfiles){
                if(!(Test-Path -Path "$DataCollectionDir\$($folder.Name)" -PathType Container)){
                    New-Item -Path "$DataCollectionDir\$($folder.Name)" -ItemType Directory
                }
                if($file.Parent -ne "CrashDumps"){
                    if(($null -eq $using:FromDate -or $file.LastWriteTime -ge $using:FromDate) -and ($null -eq $using:ToDate -or $file.LastWriteTime -le $using:ToDate))
                    {
                        Copy-Item $file.FullName -Destination "$DataCollectionDir\$($folder.Name)"
                    }
                }
            }
        }


        $EventLogs = @()
        $EventLogs += Get-WinEvent -ListLog Application
        $EventLogs += Get-WinEvent -ListLog System

        Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting role specific logs" -PercentComplete 20

        if($role -eq "NC")
        {
            # Collect Logs for network controller role
            New-Item -Path "$DataCollectionDir\ServiceFabric" -ItemType Directory | Out-Null

            # SF logs are large, allow maximum 1 hours logs to be collected
            $ToDateSf = $($using:FromDate).AddHours(1)
            if($null -ne $using:ToDate -and $using:ToDate -lt $ToDateSf)
            {
                $ToDateSf = $using:ToDate
            }
            $SFLogs = Get-ChildItem -Path "C:\ProgramData\Microsoft\Service Fabric\log\Traces" | Where-Object {
                $_.LastWriteTime -ge $using:FromDate -and $_.LastWriteTime -le $ToDateSf
            }
            foreach($SFLog in $SFLogs)
            {
                Copy-Item $SFLog.FullName -Destination "$DataCollectionDir\ServiceFabric"
            }

            $EventLogs += Get-WinEvent -ListLog *NetworkController* | Where-Object {$_.RecordCount}
            $EventLogs += Get-WinEvent -ListLog *ServiceFabric* | Where-Object {$_.RecordCount}

            ### Get IMOS DB Info
            #Collect SF Cluster IMOS DB File info
            $sfClusterConnection = Connect-ServiceFabricCluster
            if($sfClusterConnection)
            {
                Write-Log "Collecting Network Controller IMOS Store Info"
                $ncServices = Get-ServiceFabricService -ApplicationName "fabric:/NetworkController"
                # service fabric base folder
                $svcFabricPath = "C:\ProgramData\Microsoft\Service Fabric\$(HostName)\Fabric\work\Applications\NetworkController_App0\work"
                $imosInfo = @()
                foreach($ncService in $ncServices)
                {
                    #Get partition ID
                    $partitionId = (Get-ServiceFabricPartition -ServiceName $ncService.ServiceName).PartitionId
                    $imosPath = Join-Path -Path $svcFabricPath -ChildPath "P_$partitionId"
                    #Get replica ID
                    $replicaId = (Get-ServiceFabricReplica -PartitionId $partitionId | Where-Object NodeName -EQ $(HostName)).ReplicaId
                    $path = Join-Path -Path $imosPath -ChildPath "R_$replicaId\ImosStore"
                    if(Test-Path $path)
                    {
                        #Write-Host "[$(HostName)] $($ncService.ServiceName) IMOS Size: $((Get-Item $path).length)"
                        $imosFile = Get-Item $path
                        $imosInfo += [PSCustomObject]@{
                        NC = $(HostName)
                        ServiceName = $ncService.ServiceName
                        ServicePartitionId = $partitionId
                        ImosSizeinKB = ($imosFile.length)/1KB
                        LastWriteTime = $imosFile.LastWriteTime
                        }
                    }

                }
                $imosInfo | ft | Out-File -FilePath "$DataCollectionDir\IMOSDBInfo.txt"
                logman query | Out-File -FilePath "$DataCollectionDir\LogmanStatus.txt"

                Write-Log "Collecting Network Controller Status"
                New-Item -Path "$DataCollectionDir\NetworkControllerStatus" -ItemType Directory | Out-Null
                $client = [System.Fabric.FabricClient]::new()
                $task = $client.PropertyManager.EnumeratePropertiesAsync("fabric:/NetworkController/GlobalConfiguration", $true, $null)
                $task.Result | ForEach-Object {$name=$_.Metadata.PropertyName; $value=[System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([string]).Invoke($_, $null); "Name:"+$name +", "+ "Value:"+$value} >> "$DataCollectionDir\NetworkControllerStatus\GlobalConfiguration.txt"

                $NCUri = "fabric:/NetworkController"
                Get-ServiceFabricClusterManifest | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\ClusterManifest.xml"
                Get-ServiceFabricClusterHealth | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\ClusterHealth.txt"

                $NCApp = Get-ServiceFabricApplication -ApplicationName $NCUri
                $NCApp | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCApp.txt"
                Get-ServiceFabricApplicationManifest -ApplicationTypeName $NCApp.ApplicationTypeName -ApplicationTypeVersion $NCApp.ApplicationTypeVersion | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCAppManifest.txt"
                Get-ServiceFabricApplicationHealth -ApplicationName $NCUri | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCAppHealth.txt"
                Get-ServiceFabricApplicationUpgrade -ApplicationName fabric:/NetworkController | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCUpgrade.txt"

                $NCServices = Get-ServiceFabricService -ApplicationName $NCUri
                $NCServices | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCServices.txt"
                foreach ($service in $NCServices){
                    $serviceTypeName=$service.ServiceTypeName
                    Get-ServiceFabricServiceHealth -ServiceName $service.ServiceName.AbsoluteUri | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt"

                    $partition = Get-ServiceFabricPartition -ServiceName $service.ServiceName.AbsoluteUri
                    $replicas = Get-ServiceFabricReplica -PartitionId $partition.PartitionId
                    $replicas | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt"
                    foreach($replica in $replicas){
                        if($replica.ReplicaId){
                            Get-ServiceFabricReplicaHealth -PartitionId $partition.PartitionId -ReplicaOrInstanceId $replica.ReplicaId >> "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt"
                        }
                        else {
                            Get-ServiceFabricReplicaHealth -PartitionId $partition.PartitionId -ReplicaOrInstanceId $replica.InstanceId >> "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt"
                        }
                    }
                }

            }else
            {
                Write-Log "Failed to connect to Service Fabric Cluster" -Type "Error"
            }


        }elseif($role -eq "MUX")
        {
            Write-Log "Collecting MUX Logs"
            # Collect Logs for MUX role
            $EventLogs += Get-WinEvent -ListLog *SLBMux* | Where-Object {$_.RecordCount}

            # MUX Driver Control Console Output
            MuxDriverControlConsole.exe /GetMuxState | Out-File "$DataCollectionDir\MuxState.txt"
            MuxDriverControlConsole.exe /GetMuxConfig | Out-File "$DataCollectionDir\MuxConfig.txt"
            MuxDriverControlConsole.exe /GetMuxStats | Out-File "$DataCollectionDir\MuxStats.txt"
            MuxDriverControlConsole.exe /GetMuxVipList | Out-File "$DataCollectionDir\MuxVipList.txt"
            MuxDriverControlConsole.exe /GetMuxVip | Out-File "$DataCollectionDir\MuxVips.txt"
            MuxDriverControlConsole.exe /GetMuxDripList | Out-File "$DataCollectionDir\MuxDripList.txt"
            MuxDriverControlConsole.exe /GetStatelessVip | Out-File "$DataCollectionDir\StatelessVip.txt"
            MuxDriverControlConsole.exe /GetStatefulVip | Out-File "$DataCollectionDir\StatefulVip.txt"
        }
        elseif($role -eq "GW")
        {
            Write-Log "Collecting Gateway Logs"
            # Collect Logs for GW
            $EventLogs += Get-WinEvent -ListLog *RemoteAccess* | Where-Object {$_.RecordCount}
            $EventLogs += Get-WinEvent -ListLog *VPN* | Where-Object {$_.RecordCount}
            $EventLogs += Get-WinEvent -ListLog *IKE* | Where-Object {$_.RecordCount}

            Get-RemoteAccess | Out-File "$DataCollectionDir\Get-RemoteAccess.txt"
            Get-VpnServerConfiguration | Out-File "$DataCollectionDir\Get-VpnServerConfiguration.txt"
            Get-VpnS2SInterface | Format-List * | Out-File "$DataCollectionDir\Get-VpnS2SInterface.txt"
            Get-GatewayTunnel | Format-List * | Out-File "$DataCollectionDir\Get-GatewayTunnel.txt"
            Get-RemoteaccessRoutingDomain | Format-List * | Out-File "$DataCollectionDir\Get-RemoteAccessRoutingDomain.txt"
            foreach ($routingDomain in Get-RemoteAccessRoutingDomain){
                New-Item -Path "$DataCollectionDir\$($routingDomain.RoutingDomainID)" -ItemType Directory | Out-Null
                Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpRouter.txt"
                Get-BgpPeer -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpPeer.txt"
                Get-BgprouteInformation -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpRouteInformation.txt"
                Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpCustomRoute.txt"
            }
            Set-Content -Path "$DataCollectionDir\README.txt" -Value "ETL files to be decoded using InsightClient"
            # Ensure we cleanup RAS logs from tracing
            # Remove-Item -Path "C:\Windows\Tracing\*.log"
            # Remove-Item -Path "C:\Windows\Tracing\*.etl"
        }elseif($role -eq "HyperV")
        {
            Write-Log "Collecting Hyper-V Logs"
            $EventLogs += Get-WinEvent -ListLog *Hyper-V* | Where-Object {$_.RecordCount}
             # Gather VFP port configuration details
            New-Item -Path "$DataCollectionDir\VFP" -ItemType Directory -Force | Out-Null

            Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting VM Network Adapter Info for Guest" -PercentComplete 25
            Write-Log "Getting VM Adapter Port Info for Guest"
            $vmAdapters = Get-VMNetworkAdapter *
            $VMAdapterPortInfos = @()
            $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
            $index = 0
            foreach($vmAdapter in $vmAdapters){
                Write-Log "Getting VM Adapter Port Info for $vmAdapter"
                Write-Progress -Activity "Collecting VM Network Adapter Info" -Status "$vmAdapter" -PercentComplete $($index * 100/$vmAdapters.count)
                $PortSettings = $vmAdapter | Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
                $portDatas = Get-VMSwitchExtensionPortData -VMNetworkAdapter $vmAdapter
                if($portDatas.Count -gt 0)
                {
                    $portid = $portDatas[0].data.deviceid
                }else
                {
                    continue
                }
                foreach($PortSetting in $PortSettings){
                    $VMAdapterPortInfo = [PSCustomObject]@{
                            VMName = $vmAdapter.VMName
                            VMAdapterName= $vmAdapter.Name;
                            PortId = $portid
                            PortProfileId = $PortSetting.SettingData.ProfileId
                            PortProfileName = $PortSetting.SettingData.ProfileName

                        }
                    $VMAdapterPortInfos += $VMAdapterPortInfo
                }
                $index ++
            }

            Write-Log "Getting VM Adapter Port Info for ManagementOS"
            Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting VM Network Adapter Info for Management OS" -PercentComplete 30
            $mgmtVmAdapters = Get-VMNetworkAdapter -ManagementOS
            $index = 0
            foreach($mgmtVmAdapter in $mgmtVmAdapters)
            {
                Write-Log "Getting VM Adapter Port Info for $mgmtVmAdapter"
                Write-Progress -Activity "Collecting VM Network Adapter Info" -Status "$mgmtVmAdapter" -PercentComplete $($index * 100/$mgmtVmAdapters.count)
                $portid = (Get-VMSwitchExtensionPortData -ManagementOS -VMNetworkAdapterName $mgmtVmAdapter.Name)[0].data.deviceid
                $VMAdapterPortInfo = [PSCustomObject]@{
                    VMName = "ManagementOS"
                    VMAdapterName= $mgmtVmAdapter.Name
                    PortId = $portid
                    PortProfileId = $null
                    PortProfileName = $null
                }
                $VMAdapterPortInfos += $VMAdapterPortInfo
                $index ++
            }

            $VMAdapterPortInfos | Out-File "$DataCollectionDir\VMNetworkAdapterPort.txt"

            Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting VFP info for VM Network Adapters" -PercentComplete 35
            foreach($vmAdapterPort in $VMAdapterPortInfos)
            {
                vfpctrl.exe /list-rule /port:$($vmAdapterPort.PortId) | Out-File "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_RuleInfo.txt"
                vfpctrl.exe /list-nat-range /port $($vmAdapterPort.PortId) | Out-File "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_NatInfo.txt"
                vfpctrl.exe /list-mapping /port $($vmAdapterPort.PortId) | Out-File "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_ListMapping.txt"
                vfpctrl.exe /get-port-flow-settings /port:$($vmAdapterPort.PortId) | out-file "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_PortFlowSettings.txt"
                vfpctrl.exe /get-port-flow-stats /port:$($vmAdapterPort.PortId) | out-file "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_UnifiedFlowStats.txt"
                vfpctrl.exe /get-flow-stats  /port:$($vmAdapterPort.PortId) | out-file "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_LayerFlowStats.txt"
            }
            Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting OVSDB dump" -PercentComplete 40
             # Gather OVSDB databases
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Out-File "$DataCollectionDir\ovsdb_vtep.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Out-File "$DataCollectionDir\ovsdb_firewall.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion | Out-File "$DataCollectionDir\ovsdb_serviceinsertion.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep -f json -pretty| Out-File "$DataCollectionDir\ovsdb_vtep.json"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall -f json -pretty | Out-File "$DataCollectionDir\ovsdb_firewall.json"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion | Out-File "$DataCollectionDir\ovsdb_serviceinsertion.json"
            vfpctrl /list-vmswitch-port | Out-File "$DataCollectionDir\vfpctrl_list-vmswitch-port.txt"

            Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting Hyper-V vSwitch Info" -PercentComplete 45
            # Gather Hyper-V network details
            Get-PACAMapping | Sort-Object PSComputerName | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-PACAMapping.txt"
            Get-ProviderAddress | Sort-Object PSComputerName | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-ProviderAddress.txt"
            Get-CustomerRoute | Sort-Object PSComputerName | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-CustomerRoute.txt"
            Get-NetAdapterVPort | Out-File "$DataCollectionDir\Get-NetAdapterVPort.txt"
            Get-NetAdapterVmqQueue | Out-File "$DataCollectionDir\Get-NetAdapterVMQQueue.txt"
            Get-VMSwitch | Format-List * | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-VMSwitch.txt"
            Get-VMNetworkAdapterIsolation | Out-File "$DataCollectionDir\Get-VMNetworkAdapterIsolation.txt"
            Get-VMNetworkAdapterRoutingDomainMapping | Out-File "$DataCollectionDir\Get-VMNetworkAdapterRoutingDomainMapping.txt"
            $vmSwitches = Get-VMSwitch
            $vmSwitch  | Format-List * | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-VMSwitch.txt"

            foreach($vmSwitch in $vmSwitches)
            {
                if($vmSwitch.EmbeddedTeamingEnabled -eq $true){
                    Get-VMSwitchTeam -Name $vmSwitch.Name | Format-List * | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-VMSwitchTeam.txt" -Append
                }
            }

            Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting Nc Host Agent Info" -PercentComplete 48
            # Gather registry key properties for nchostagent and other nc services
            $RegKeyDirectories = @()
            $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent
            $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent -Recurse
            if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\DnsProxy"){
                $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\DnsProxy
                $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\DnsProxy -Recurse
            }

            $RegKeyDirectories = $RegKeyDirectories | Sort-Object -Unique

            foreach($obj in $RegKeyDirectories){
                if($obj.PSPath -like "*NCHostAgent*"){
                    Get-ItemProperty -Path $obj.PSPath | Out-File -Encoding ascii "$DataCollectionDir\Registry_NCHostAgent.txt" -Append
                }
                if($obj.PSPath -like "*DnsProxy*"){
                    Get-ItemProperty -Path $obj.PSPath | Out-File -Encoding ascii "$DataCollectionDir\Registry_DnsProxy.txt" -Append
                }
            }

            # [RS5] Gather nvspinfo.exe results
            if([System.Environment]::OSVersion.Version.Build -eq '17763'){
                nvspinfo.exe -e | Out-File -FilePath "$DataCollectionDir\NVSPInfo.txt"
            }
        }

        Write-Log "Procesing Event Logs"
        $EventLogFolder = "$DataCollectionDir\EventLogs"
        if(!(Test-Path -Path $EventLogFolder -PathType Container)){
            New-Item -Path $EventLogFolder -ItemType Directory -Force | Out-Null
        }

        Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting Event Logs" -PercentComplete 50
        foreach ($EventLog in $EventLogs){
            #Get-WinEvent -LogName $EventLog.LogName | Where-Object {$_.TimeCreated -gt $using:FromDate} | Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, ProviderID, TaskDisplayName, OpCodeDisplayName, Message | Export-Csv -Path "$EventLogFolder\$($EventLog.LogName).csv".Replace("/","_") -NoTypeInformation
            wevtutil epl $EventLog.LogName "$EventLogFolder\$($EventLog.LogName).evtx".Replace("/","_")
        }

        Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting OS Configuration" -PercentComplete 60
        # Gather general configuration details from all nodes
        Get-ComputerInfo | Out-File "$DataCollectionDir\Get-ComputerInfo.txt"
        Get-Hotfix | Out-File "$DataCollectionDir\Get-Hotfix.txt"
        Get-NetAdapter | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-NetAdapter.txt"
        foreach($NetAdapter in Get-NetAdapter){
            Get-NetAdapter -Name $NetAdapter.Name | Format-List * | Out-File "$DataCollectionDir\Get-NetAdapter_$($NetAdapter.Name).txt"
            Get-NetAdapterAdvancedProperty -Name $NetAdapter.Name | Format-List * | Out-File "$DataCollectionDir\Get-NetAdapterAdvancedProperty_$($NetAdapter.Name).txt"
        }

        Get-Service | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-Service.txt"
        Get-Process | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-Process.txt"
        ipconfig /allcompartments /all | Out-File "$DataCollectionDir\ipconfig_allcompartments.txt"
        Get-NetIPInterface -IncludeAllCompartments | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-NetIPInterface.txt"
        Get-NetNeighbor -IncludeAllCompartments | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-NetNeighbor.txt"
        Get-NetRoute -AddressFamily IPv4 -IncludeAllCompartments | Out-File "$DataCollectionDir\Get-NetRoute.txt"
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-Csv -Path "$DataCollectionDir\Get-NetTCPConnection.csv" -NoTypeInformation

        Get-Volume | ft | Out-file "$DataCollectionDir\Get-Volume.txt"

        Write-Log "Collecting Certificates Information"
        Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting Certificate Information" -PercentComplete 70
        # Gather certificates from all nodes
        $CertLocationPaths = @(
        'Cert:\LocalMachine\My'
        'Cert:\LocalMachine\Root'
        )
        foreach ($CertLocation in $CertLocationPaths){
            $Certificates = @()
            $CertificateList = Get-ChildItem -Path $CertLocation -Recurse | Where-Object {$_.PSISContainer -eq $false}
            foreach($cert in $CertificateList){
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $cert.FriendlyName
                $obj | Add-Member -MemberType NoteProperty -Name "Subject" -Value $cert.Subject
                $obj | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $cert.Issuer
                $obj | Add-Member -MemberType NoteProperty -Name "Thumbprint" -Value $cert.Thumbprint
                $obj | Add-Member -MemberType NoteProperty -Name "HasPrivateKey" -Value $cert.HasPrivateKey
                $obj | Add-Member -MemberType NoteProperty -Name "PrivateKey" -Value $cert.PrivateKey
                $obj | Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $cert.NotBefore
                $obj | Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $cert.NotAfter
                $obj | Add-Member -MemberType NoteProperty -Name "Archived" -Value $cert.Archived
                $obj | Add-Member -MemberType NoteProperty -Name "DnsNameList" -Value $cert.DnsNameList
                $obj | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $cert.SerialNumber
                $obj | Add-Member -MemberType NoteProperty -Name "EnhancedKeyUsageList" -Value $cert.EnhancedKeyUsageList
                if($cert.PrivateKey){
                    $acl = Get-Acl -Path ("$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\" + $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)
                    $obj | Add-Member -MemberType NoteProperty -Name "AccesstoString" -Value $acl.AccessToString
                    $obj | Add-Member -MemberType NoteProperty -Name "Sddl" -Value $acl.Sddl
                }
                $Certificates += $obj
            }
            $DirFriendlyName = $CertLocation.Replace(":","").Replace("\","_")
            $Certificates | Export-Csv -NoTypeInformation "$DataCollectionDir\$DirFriendlyName.csv"
        }

        Write-Log "Collecting NetSetup Logs"
        Write-Progress -Activity "[$(HostName)] Log collection" -Status "Collecting NetSetup Logs" -PercentComplete 80
        # Gather files related to network setup from all nodes
        $NetSetupFiles = @(
            "$env:SystemRoot\Panther\setupact.log"
            "$env:SystemRoot\INF\setupapi.*"
            "$env:SystemRoot\logs\NetSetup\*"
        )

        New-Item "$DataCollectionDir\NetSetupLogs" -ItemType Directory | Out-Null
        foreach($file in $NetSetupFiles){
            Copy-Item -Path $file -Destination "$DataCollectionDir\NetSetupLogs"
        }

        Write-Log "Data Collection Completed"
    } -ArgumentList $Role,$DataCollectionDir
    # -AsJob -JobName ($Id = "$([guid]::NewGuid())")

    # Monitor the job status
    #Get-JobStatus -JobName $Id -ExecutionTimeOut 300 -PollingInterval 1

    # Copy the logs
    $index = 0;
    foreach($InfraNode in $InfraNodes)
    {
        $completePercent = $index * 100 / $InfraNodes.Count;
        Write-Progress -Activity "Log Copy" -Status "Copy log from $InfraNode" -PercentComplete $completePercent
        Write-Log "Copying logs from $InfraNode to $OutputPath"
        $RemotePathToCopy = "\\$InfraNode\c$\Temp\CSS_SDN\*"
        New-Item -Path "$OutputPath\$InfraNode" -ItemType Directory -Force | Out-Null
        Copy-Item -Path $RemotePathToCopy -Destination "$OutputPath\$InfraNode" -Recurse | Out-null
        $index ++;
    }
}

Function Get-OutputPath
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $OutputPath
    )
    if([String]::IsNullOrEmpty($OutputPath))
    {
        $OutputPath = Get-Date -Format "yyyyMMddHHmmss"
        Write-Log "Creating log path $OutputPath"
        New-Item $OutputPath -ItemType Directory -Force | Out-Null
    }
    return $OutputPath
}

Function Clear-SdnHostLogs
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]]
        $SdnHosts
    )
    Invoke-Command -ComputerName $SdnHosts -ScriptBlock{
        Param(
            [bool]$IncludeVfp
        )
        Write-Host "[$(HostName)]Cleanning up c:\SDNHostTrace"
        $HostLogPath = "C:\SDNHostTrace"
        if(Test-Path $HostLogPath){
            Write-Host "[$(HostName)]Log path $HostLogPath existed, remove the old logs and recreate"
            Remove-Item -Path $HostLogPath -Recurse -Force
        }
        New-Item -Path $HostLogPath -ItemType Directory -Force
        Write-Host "[$(HostName)]Log path $HostLogPath created and cleaned up"
    }
}


Function Get-SdnVirtualServerAddress
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]
        $NcUri,
        [String]
        [Parameter(Mandatory=$True)]
        $ResourceId
    )

    #Write-Log "Getting Virtual Server from $NcUri with resource Id: $ResourceId"
    $virtualServerResource = Get-NetworkControllerVirtualServer -ConnectionUri $NcUri -ResourceId $ResourceId

    if($virtualServerResource -ne $null)
    {
        #Write-Log "Looking for Virtual Server Connections"
        if($virtualServerResource.properties.connections -ne $null)
        {
            #Write-Log "Looking for Virtual Server Connection Management Address"
            if($virtualServerResource.properties.connections[0].managementaddresses -ne $null)
            {
                return $virtualServerResource.properties.connections[0].managementaddresses[0]
            }
        }
    }

    #Write-Log "No Virtual Server resource found"
    return ""
}

Function Get-SdnInfraInfo{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $NcVMName
    )

    Write-Log "Getting SDN Infra Info from $NcVMName"
    $NcUri = Get-SdnNcUri -NcVMName $NcVMName
    # Validate NcUri is reachable before proceed
    Try{
        $response = Invoke-WebRequest "$NcUri/networking/v1/servers" -UseBasicParsing -UseDefaultCredentials -Verbose:$false
    }catch{
        Write-Log "Failed to access $NcUri/networking/v1/servers" -Type Error
        Write-Log "Exception: $_" -Type Error
        Write-Log "Ensure the NC Certificate is Trusted by current machine, Run 'Intall-SdnNcCert -NcVMName <NC VM Name>' to install the NC Cert if NC is using self-signed cert"
        throw "NC URI failed to access"
    }
    Write-Log "Looking for SDN NC"

    $SdnInfraInfo = @{}
    $NcVMs = (Get-NetworkControllerNode -ComputerName $NcVMName).Server
    $MuxVMs = Get-SdnInfraNodes -NcVMName $NcVMName -RoleType "MUX"
    $GwVMs = Get-SdnInfraNodes -NcVMName $NcVMName -RoleType "Gateway"
    $SdnHosts = Get-SdnInfraNodes -NcVMName $NcVMName -RoleType "Server"
    $SdnInfraInfo = [PSCustomObject]@{
        NcUri = $NcUri
        NC = $NcVMs
        Mux = $MuxVMs
        Gateway = $GwVMs
        Host = $SdnHosts
    }
    return $SdnInfraInfo
}

Function Get-SdnNcVmNameFromHost()
{
    $NCVMName = ""
    Write-Log "Trying to find RESTNAME automatically"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\NcHostAgent")
    {
        Write-Log "Getting RESTNAME from NCHOSTAGENT Registry"
        $registry = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NcHostAgent\Parameters"
        if ($regsitry.Connections)
        {
            $RestName=$registry.Connections[0].Split(":")[1]
        }
        else
        {
            #Trying with Cert CNAME
            $RestName=$registry.PeerCertificateCName
        }
        Write-Log "RestName retrieved is $RestName"
            # Getting one NC Name from DNS
        try{
            $RestIP=(Resolve-DnsName $RestName -ErrorAction Stop).IpAddress
            Write-Log "$RestName resolved to $RestIp"
            $NCVMName=(Resolve-DnsName $RestIP -ErrorAction Stop).Namehost
            Write-Log "$RestIP resolved to $NCVMName"
        }Catch
        {
            Write-Log "$RestIP not resolved"
        }

    }else{
        Write-Log "This is not executing from SDN host, please specifiy the NC VM name"
    }
    return $NCVMName
}

# Install NC Cert if NC Rest Cert Not trusted by the current machine running script. Ask user's confirmation
Function Install-SdnNcCert
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $NCVMName
    )
    $ncConfig = Invoke-Command -ComputerName $NCVMName -ScriptBlock{
        $ncConfig = Get-NetworkController
        $ncRestName = $ncConfig.RestName
        $ncCertThumb = $ncConfig.ServerCertificate.Thumbprint
        Get-ChildItem Cert:LocalMachine\My\$ncCertThumb | Export-Certificate -Type CERT -FilePath "c:\Temp\CSS_SDN\$ncRestName" | out-null
        return $ncConfig
    }

    $ncCertThumb = $ncConfig.ServerCertificate.Thumbprint
    $ncRestName = $ncConfig.RestName
    if(Test-Path Cert:LocalMachine\Root\$ncCertThumb)
    {
        Write-Log "NC Cert $ncCertThumb trusted, continue"
        return $true
    }else{
        Write-Log "NC Cert $ncCertThumb not trusted. Need import" -Type Warning
        Import-Certificate -FilePath "\\$NCVMName\c$\Temp\CSS_SDN\$ncRestName" -certstorelocation "cert:\localmachine\root" -Confirm | out-null
        if(Test-Path Cert:LocalMachine\Root\$ncCertThumb)
        {
            Write-Log "NC Cert installed. Continue"
            return $true
        }else
        {
            return $false
        }
    }
}

Function Start-SdnMuxTrace
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]]
        $MuxVMs
    )

    if($MuxVms.Count -gt 0){
        Invoke-Command -ComputerName $MuxVms -ScriptBlock{
            $TraceDir = "C:\Temp\CSS_SDN\Traces"

            # Stop the trace if that is running
            $sessionNames = @("muxtrace")
            $allEtwSessions = Get-EtwTraceSession *
            foreach($sessionName in $sessionNames)
            {
                $etwSession = $allEtwSessions | where name -eq $sessionName
                if($null -ne $etwSession)
                {
                    Write-Host "[$(HostName)] Existing trace session $sessionName found, stop it"
                    $etwSession | Stop-EtwTraceSession
                }
            }

            # Cleanup the traces folder before start new trace
            if(Test-Path $TraceDir){
                Write-Host "[$(HostName)] Log path $TraceDir existed, remove the old logs and recreate"
                Remove-Item "$TraceDir\*" -Recurse -Force
            }else{
                New-item -Path $TraceDir -ItemType Directory -Force
            }

            logman create trace "muxtrace" -ow -o "$TraceDir\mux.etl" -p "{645b8679-5451-4c36-9857-a90e7dbf97bc}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
            logman update trace "muxtrace" -p "{6C2350F8-F827-4B74-AD0C-714A92E22576}" 0xffffffffffffffff 0xff -ets

            Write-Host "Started MUX Trace at $(HostName)"
        }
    }else {
        Write-Error "No MUX VM Specified"
        return
    }
}

Function Stop-SdnMuxTrace{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String[]]
        $MuxVMs
    )

    if($MuxVms.Count -gt 0){
        Invoke-Command -ComputerName $MuxVms -ScriptBlock{
            Write-Host "Stopping MUX Trace at $(HostName)"
            logman stop "muxtrace" -ets
        }
    }else
    {
        Write-Error "No MUX VM Specified"
        return
    }
}

Function Start-SdnGatewayTrace
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]]
        $GatewayVms
    )

    if($GatewayVms.Count -gt 0){
        Invoke-Command -ComputerName $GatewayVms -ScriptBlock{
            $TraceDir = "C:\Temp\CSS_SDN\Traces"

            # Stop the trace if that is running
            $sessionNames = @("iketrace")
            $allEtwSessions = Get-EtwTraceSession *
            foreach($sessionName in $sessionNames)
            {
                $etwSession = $allEtwSessions | where name -eq $sessionName
                if($null -ne $etwSession)
                {
                    Write-Host "[$(HostName)] Existing trace session $sessionName found, stop it"
                    $etwSession | Stop-EtwTraceSession
                }
            }
            # Cleanup the traces folder before start new trace
            if(Test-Path $TraceDir){
                Write-Host "[$(HostName)] Log path $TraceDir existed, remove the old logs and recreate"
                Remove-Item "$TraceDir\*" -Recurse -Force
            }else{
                New-item -Path $TraceDir -ItemType Directory -Force
            }

            logman create trace "iketrace" -ow -o "$TraceDir\ike.etl" -p "{106b464d-8043-46b1-8cb8-e92a0cd7a560}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

            Write-Host "Started iketrace $(HostName)"
        }
    }else {
        Write-Error "No Gateway VM Specified"
        return
    }
}

Function Stop-SdnGatewayTrace
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String[]]
        $GatewayVms
    )

    if($GatewayVms.Count -gt 0){
        Invoke-Command -ComputerName $GatewayVms -ScriptBlock{
            Write-Host "Stopping Gateway Trace at $(HostName)"
            logman stop "iketrace" -ets
        }
    }else
    {
        Write-Error "No Gateway VM Specified"
        return
    }
}
