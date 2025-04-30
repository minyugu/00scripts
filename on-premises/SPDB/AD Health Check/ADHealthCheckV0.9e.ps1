<# 
    version 0.9e2

    Windows Active Directory Connectivity Check script.
    This script checks connectivity to AD servers in parallel, logs results, and does not require storing credentials in a file.
    The script uses the identity of the scheduled task that executes it for enhanced security.
#>
$datetime = Get-Date
#region Configuration
$serversPath = "D:\rpcmonitor\AD_HealthCheck\servers.txt" # File containing the list of AD server names or IP addresses
$logDir = "D:\rpcmonitor\AD_HealthCheck\Logs" # Directory for log files
$TimeoutSeconds = 60 # Timeout value in seconds for each server check

$parallelServerNum = 12
#endregion

#region check server list file and log folder and name
# Check if the server list exists
if (-not (Test-Path $serversPath)) {
    Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Error -Message "Server list file <$serversPath> not found!"
    return
}

# Check if the log folder exists
if (-not (Test-Path $logDir)) {
    try {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop | Out-Null 
    }
    catch {
        Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Error -Message "log folder <$logDir> can't be created."
        return
    }
}

# Generate log file name (one per day)
$logFile = Join-Path $logDir ("HealthCheck_{0:yyyyMMdd}.csv" -f (Get-Date))

# Initialize the list of servers
try {
    $servers = Get-Content $serversPath
}
catch {
    Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Error -Message "Can not get content of Server list file <$logDir>."
    return
}

# remove null, empty string and spaces
$servers = $servers | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { "$($_.Trim()).spdbbiz.com" }
#$servers = $servers | Select-Object -First 10
#endregion

### the check starts from here...
Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Information `
               -Message "Start excute AD Health check to out put log to file <$logFile>."

$parallelServers = @()
for ($i=0; $i -lt $servers.Count; $i += $parallelServerNum) {
    $parallelServers += ,($servers[$i..($i + $parallelServerNum -1)])
}

# 10 run in parallel
$outputCount = 0  #count succeed output server 
$errorServers = @() #record failed output server name
foreach ($parallelServer in $parallelServers) {
    #region Start jobs in parallel for each server
    $jobsWithServerName = @()
    foreach ($server in $parallelServer) {
        $job = Start-Job -Name $server -ScriptBlock {
            param($server)
            
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            # Step 1: Ping the server---------------------------------
            $pingMessage = $null
            $pingSuccess = $null
            $pingLatency = $null
    <#        try {
                #$pingResult = Test-Connection $server -Count 1 -ErrorAction Stop
                $ping = New-Object System.Net.NetworkInformation.Ping
                $pingResult = $ping.Send($server, 1000)

                # Check if the server is reachable
                if ($pingResult.Status -eq 'Success') {
                    $pingMessage = "$server is reachable."
                    $pingSuccess = $true
                    $pingLatency = $pingResult.RoundtripTime
                } else {
                    $pingMessage = "$server is unreachable."
                    $pingSuccess = $false
                    $pingLatency = "N/A"
                }
            } catch {
                # Handle any exceptions (e.g., network issues)
                $pingMessage = "Failed to ping $server. Error: $_"
                $pingSuccess = $false
                $pingLatency = "N/A"
            }
    #>
            try {
                $pingResult = Test-Connection $server -Count 1 -ErrorAction Stop
                # Check if the server is reachable
                if ($null -ne $pingResult) {
                    $pingMessage = "$server is reachable."
                    $pingSuccess = $true
                    $pingLatency = $pingResult.ResponseTime
                } else {
                    $pingMessage = "$server is unreachable."
                    $pingSuccess = $false
                    $pingLatency = "N/A"
                }
            } catch {
                # Handle any exceptions (e.g., network issues)
                $pingMessage = "Failed to ping $server. Error: $_"
                $pingSuccess = $false
                $pingLatency = "N/A"
            }

            # return ping result
            "PingStatus=$(if($pingSuccess){'Success'}else{'Failed'})"
            "PingLatency=$($pingLatency)"
            "PingMessage=$($pingMessage)"

    <# for time out test
            #if ($server -eq "corp-dc-01.corp.omygu.com") {
            if ($server -eq "sha-dc-01.sha.corp.omygu.com") {
                Start-Sleep 15
            }
    #>
            # Step 2: check LDAP connectivity---------------------------------
            $ldapConnection = $null
            $ldapMessage = $null
            $ldapConnSucess = $null
            try {
                $currentErrorAction = $ErrorActionPreference
                $ErrorActionPreference = 'Stop'

                # load System.DirectoryServices.Protocols.dll assembly
                Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop | Out-Null

                # Using LDAP port (389 for non-SSL or 636 for SSL) to check DC connectivity
                $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($server) -ErrorAction Stop
                $ldapConnection.Bind() | Out-Null  # Attempt to bind to the server
           
                $ldapMessage = "$server - LDAP connection successful."
                $ldapConnSucess = $true
            } catch {
                $ldapMessage = "$server - Failed to connect to LDAP. Error: $_"
                $ldapConnSucess = $false
            }
            $ErrorActionPreference = $currentErrorAction 

            # return LDAP Connect result
            "LdapConnectStatus=$(if($ldapConnSucess){'Success'}else{'Failed'})"
            "LdapConnectMessage=$($ldapMessage)"
            if ($null -ne $ldapConnection) {
                try {
                    [void]$ldapConnection.Dispose() # close connecton
                } catch {}
            }
            "CheckTaskSec=$($timer.Elapsed.TotalSeconds)"
        } -ArgumentList $server
    
        $jobsWithServerName += [PSCustomObject]@{
            ServerName = $server
            Job = $job
        }
    }
    #endregion

    #region Monitor all jobs and out put checking result to CSV
    $currentErrorAction = $ErrorActionPreference #record error action preference for restore in the end
    $ErrorActionPreference = 'Stop' #set error action preference to STOP, exit script when encounter error

    #region Wait for job with 10 seconds timeout
    [void](Wait-Job -Job $jobsWithServerName.Job -Timeout $TimeoutSeconds)
    #endregion

    #region Output results of jobs
    ForEach ($xjob in $jobsWithServerName)  {
        $jobStartTime = $null
        $jobEndTime = $null
        $jobStatus = $null
        $serverName = $null
        $jobReturns = $null

        #create ps object to record job result
        $psJobResult =[PSCustomObject] @{
            JobId = ""
            ServerName = ""
            StartTime = ""
            EndTime = ""
            JobDurationSec = ""
            CheckTaskSec=""
            JobTimeOut=""
            JobStatus = ""
            PingStatus = ""
            PingLatency = ""
            PingMessage = ""
            LdapConnectStatus = ""
            LdapConnectMessage = ""
            JobStateInfo = ""
            JobErrorMsg = ""
        }

        try {
            # get job info
            $serverName = $xjob.ServerName
            $jobStartTime = $xjob.job.PSBeginTime
            $jobEndTime = $xjob.job.PSEndTime
            if ( $null -ne $xjob.job.JobStateInfo.State ) {
                $jobStatus = $xjob.job.JobStateInfo.State.ToString()
            }

            # convert Job return from String Array (5 properties) to Hash Table
            $jobReturns = Receive-Job -Job $xjob.job #-ErrorAction SilentlyContinue
            if ($null -ne $jobReturns) {
                foreach ($item in $jobReturns) {
                    $key = $null
                    $value = $null
                    $key, $value = $item -split "=", 2
                    $psJobResult.$key = $value
                }
            }

            # fill job to hashtable
            $psJobResult.JobId = $xjob.job.Id
            $psJobResult.ServerName = $serverName
            if ($jobStartTime -is [datetime]) {
                $psJobResult.StartTime = $jobStartTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
            if ($jobEndTime -is [datetime]) {
                $psJobResult.EndTime = $jobEndTime.ToString("yyyy-MM-dd HH:mm:ss")
            }

            # Job Duration Seconds and Time Out
    #        if ($xjob.Job.Id -notin $completedJobsId) { #timeout job
            if ($xjob.Job.State -eq 'Running') { #timeout job
                $psJobResult.JobDurationSec = "N/A"
                $psJobResult.JobTimeOut = "Yes"
                # check if timeout in ping check
                if ($psJobResult.PingStatus -eq "") {
                    $psJobResult.PingStatus = "TimeOut"
                    $psJobResult.PingLatency = "N/A"
                    $psJobResult.PingMessage = "Ping $serverName timeout."
                    $psJobResult.LdapConnectStatus = "NotStart"
                # check if timeout in LDAP connect check
                } elseif ($psJobResult.LdapConnectStatus -eq "") {
                    $psJobResult.LdapConnectStatus = "TimeOut"
                    $psJobResult.LdapConnectMessage = "$serverName - LDAP connection timeout."
                }
            } else { #compeleted job
                if ( ($jobStartTime -is [datetime]) -and ($jobEndTime -is [datetime]))
                {
                    $psJobResult.JobDurationSec = ($jobEndTime - $jobStartTime).TotalSeconds
                    $psJobResult.JobTimeOut = "No"
                }
            }
            # job status
            $psJobResult.JobStatus = $jobStatus
         
            # job error & job state info
            if ($xjob.job.ChildJobs -and $xjob.job.ChildJobs.Count -gt 0) {
                # job error
                $JobErrorMsgs = @()
                $JobErrorMsgs = $xjob.job.ChildJobs | ForEach-Object {
                    if ($_.Error -and $_.Error.Count -gt 0) {
                        $_.Error | ForEach-Object { $_ | Out-String }
                    }
                }
                if ($JobErrorMsgs -and $JobErrorMsgs.count -gt 0) {
                 $psJobResult.JobErrorMsg = $JobErrorMsgs -join " | "
                }

                # job state info
                $JobStateInfos = @()
                $JobStateInfos = $xjob.job.ChildJobs | ForEach-Object {
                    if ( -Not [String]::IsNullOrEmpty($_.jobstateInfo.Reason.Message) ) {
                        $_.jobstateInfo.Reason.Message
                    }
                }
                if ($JobStateInfos -and $JobStateInfos.count -gt 0) {
                 $psJobResult.JobStateInfo = $JobStateInfos -join " | "
                }
            }

            # out put CSV
            $psJobResult | Export-Csv $logFile -Append -NoTypeInformation -Encoding UTF8 -Delimiter ',' -ErrorAction Stop
            $outputCount++
        } catch {
            Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Error -Message "Cannot wirte Server '$serverName' AD Check log to <$logFile>.`n`n$($_.ToString())"
            $errorServers += $serverName
        }
    }
    $ErrorActionPreference = $currentErrorAction #set error action preference to oragional setting
    # Cleanup the job after completion
    # cannot use force, some job in process will prevent job be removed
    $jobsWithServerName.Job | Remove-Job -ErrorAction SilentlyContinue -Force
    #endregion
    #endregion
}

# finally out put success/failed log to windows event log
$runSec = ((get-date) - $datetime).Seconds
if ($outputCount -eq $servers.count)
{
    Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Information `
                   -Message "All server [$outputCount] checks completed with $runSec sec. And result have been add to file <$logFile>."
} else {
    if ($errorServers -and $errorServers.Count -gt 0) {
        $stringErrorServers = $errorServers -join "`n"
    } else {
        $stringErrorServers = "None"
    }
    Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Warning `
                   -Message "[$($servers.count-$outputCount)/$($servers.count)] servers didn't out put check result to file <$logFile> with $runSec sec.`n`nOutput Error Server list:`n$($stringErrorServers)"
}
$runSecs