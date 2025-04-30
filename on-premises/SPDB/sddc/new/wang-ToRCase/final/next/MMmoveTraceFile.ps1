###
# Sample:
# .\MMmoveTraceFile.ps1 -sourceComputer AZ-KF02-WS101 -destComputer az-kf02-wc201
#
# .\MMmoveTraceFile.ps1 -sourceComputer AZ-POC01-WC002 -destComputer POC01VMM01
###

<#
param
(
    
    [Parameter(Mandatory=$true)]
    [String]$sourceComputer,

    [Parameter(Mandatory=$true)]
    [String]$destComputer
)
#>

#     Enter-PSSession "AZ-POC01-WC002" 

#$sourceComputer = "AZ-POC01-WC002" 
$sourceComputers = @("AZ-POC01-WC001","AZ-POC01-WC001")
$destComputer = "POC01VMM01"
$destShareFolder = "C$"

if ( !$cred ) { $cred = Get-Credential poc01\ms-mygu }

$jobAndSessions = [System.Collections.ArrayList]@()

if ($sourceComputers.Count -gt 0) 
{

    foreach ($sourceComputer in $sourceComputers) 
    {
    
        $currentComputerJS = $null
        foreach($oneJobAndSession in $jobAndSessions) { if( $oneJobAndSession[0] -eq $sourceComputer ) { $currentComputerJS = $oneJobAndSession } }
        if( (!$currentComputerJS) -or ((get-job -Id $currentComputerJS[2]).State -eq "Completed") )
        {

            $ComputerSession = New-PSSession -ComputerName $sourceComputer -Credential $cred
            # move trace file net_netio$_.etl && smbserver$_.etl
            $job = Invoke-Command -Session $ComputerSession -AsJob -ScriptBlock {
                param([string]$sourceComputer,[string]$destComputer,$cred,[string]$destShareFolder)

                # get first log file
                $sourceFileNames = @("D:\net_netio*.etl", "D:\smbserver*.etl")
                foreach ($sourceFileName in $sourceFileNames) { $logs += Get-Item $sourceFileName }
                if ($logs.count -gt 0 )
                {

                    ### move trace file net_netio$_.etl && smbserver$_.etl
                    # mount SMBTracelog: driver with credential
                    $destComputerCshare = "\\" + $destComputer + "\" + $destShareFolder
                    if (!(Test-Path "SMBTracelog:\"))
                    {
                        New-PsDrive -PSProvider "Filesystem" -Root $destComputerCshare -Credential $cred -Name "SMBTracelog"
                    }

                    # create folder
                    $destPathwithHostName = "SMBTracelog:\01smbtraclog\" + $env:COMPUTERNAME
                    #Write-Host $destPathwithHostName
                    if (!(Test-Path $destPathwithHostName)) { New-Item -Path $destPathwithHostName -ItemType Directory }

                    $sourceLogFile = ($logs | sort LastWriteTime | select -First 1)
        
                    # move log
                    Write-Output "stared move file <$($sourceLogFile.Name)>. $(get-date) to $($destComputerCshare)\01smbtraclog\$env:COMPUTERNAME"
                    $sourceLogFile | Move-Item -Destination $destPathwithHostName
                    Write-Output "successed move file <$($sourceLogFile.Name)>. $(get-date)"
                    Write-Output ""
                } else {Write-Output "no file to move"}

            } -ArgumentList $sourceComputer, $destComputer, $cred, $destShareFolder

            $jobAndSession = @($sourceComputer, $ComputerSession.Id, $job.Id)
            $jobAndSessions.Add($jobAndSession)
        }
    }
}

if ($jobAndSessions.Count -gt 0)
{
    foreach($oneJobAndSession in $jobAndSessions) {
        if( (get-job -Id $oneJobAndSession[2]).State -eq "Completed" ) {
            start-sleep 1
            Write-Output ("$($oneJobAndSession[0]) computer job complete ===============$(get-date)====================")
            Write-Output ((get-job -Id $oneJobAndSession[2]).ChildJobs[0].Output)
            # remove complete list
            $jobAndSessions.Remove($oneJobAndSession)
            # Out-File -FilePath $filePath -Width 1000 -InputObject ($Massage) -Encoding utf8 -Append 
            # Remove-PSSession -Id $ComputerSession.Id
        } else {
            Write-Output (get-job)
        }
    }
}

start-sleep 5

#New-PsDrive -PSProvider "Filesystem" -Root "\\POC01VMM01\c$" -Credential $cred