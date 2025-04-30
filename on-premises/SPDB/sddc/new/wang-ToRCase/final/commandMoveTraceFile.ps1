<#
$jobs = [System.Collections.ArrayList]@()
$destShareFolder = "D$"
$moveFileJob = "C:\temp\mygu_ToRCase\final\moveFileJob.log"

if(!$cred) {$cred = Get-Credential "KF02\ms-mygu"}

#===================================================================

$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS101 -destComputer az-kf02-wc201 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS102 -destComputer az-kf02-wc202 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS103 -destComputer az-kf02-wc203 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS104 -destComputer az-kf02-wc204 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS105 -destComputer az-kf02-wc205 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS106 -destComputer az-kf02-wc206 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS107 -destComputer az-kf02-wc207 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS108 -destComputer az-kf02-wc208 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS109 -destComputer az-kf02-wc209 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS110 -destComputer az-kf02-wc210 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS111 -destComputer az-kf02-wc211 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS112 -destComputer az-kf02-wc212 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS113 -destComputer az-kf02-wc213 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS114 -destComputer az-kf02-wc214 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS115 -destComputer az-kf02-wc215 -destShareFolder $destShareFolder -cred $cred))

$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS201 -destComputer az-kf02-wc216 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS202 -destComputer az-kf02-wc217 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS203 -destComputer az-kf02-wc218 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS204 -destComputer az-kf02-wc219 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS205 -destComputer az-kf02-wc220 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS206 -destComputer az-kf02-wc211 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS207 -destComputer az-kf02-wc222 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS208 -destComputer az-kf02-wc223 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS209 -destComputer az-kf02-wc224 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS210 -destComputer az-kf02-wc225 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS211 -destComputer az-kf02-wc226 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS212 -destComputer az-kf02-wc227 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS213 -destComputer az-kf02-wc228 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS214 -destComputer az-kf02-wc229 -destShareFolder $destShareFolder -cred $cred))
$jobs.add($(move-traceLogFile -sourceComputer AZ-KF02-WS215 -destComputer az-kf02-wc230 -destShareFolder $destShareFolder -cred $cred))

$jobs
out-putJobs
#===================================================================

#>



function out-putJobs
{
    $removeJobs = [System.Collections.ArrayList]@()
    foreach ($job in $jobs)
    {
        if ($job.State -eq "Completed")
        {
            Start-Sleep 1
            $Massage = $null
            $Massage = $job.ChildJobs[0] | FT Name, State, Location, output, PSBeginTime, PsEndTime, Error, Warning, Information -AutoSize
            Out-File -FilePath $moveFileJob -Width 1000 -InputObject ($Massage) -Encoding utf8 -Append
            $removeJobs.add($job)
        }
    }
    if( $removeJobs.count -gt 0)
    {
        foreach($removeJob in $removeJobs) { $jobs.Remove($removeJob) }
    }
}

function move-traceLogFile
{
    param(
    [Parameter(Mandatory=$true)]
    [String]$sourceComputer,

    [Parameter(Mandatory=$true)]
    [String]$destComputer,

    [Parameter(Mandatory=$true)]
    [String]$destShareFolder,

    [Parameter(Mandatory=$true)]
    $cred
    )

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
    return $job
}


# $jobs.add($(move-traceLogFile -sourceComputer AZ-POC01-WC001 -destComputer POC01VMM01 -destShareFolder $destShareFolder -cred $cred))
# $jobs.add($(move-traceLogFile -sourceComputer AZ-POC01-WC002 -destComputer POC01VMM01 -destShareFolder $destShareFolder -cred $cred))
# $jobs.add($(move-traceLogFile -sourceComputer AZ-POC01-WC003 -destComputer POC01VMM01 -destShareFolder $destShareFolder -cred $cred))