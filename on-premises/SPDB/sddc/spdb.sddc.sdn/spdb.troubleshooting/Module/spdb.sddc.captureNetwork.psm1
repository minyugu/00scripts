function Start-NetworkCapture
{
    param(
        [Parameter(Mandatory=$True)]
        [String[]]$servers,
        [Parameter(Mandatory=$True)]
        [String]$netCaptureLogPath,
        [Parameter(Mandatory=$True)]
        [String]$netCaptureLogSize,
        [Parameter(Mandatory=$false)]
        [String]$jobServerIp,
        [Parameter(Mandatory=$True)]
        [String]$netCpatureFilter
    )


    $jobs = Invoke-Command -ComputerName $servers -AsJob -ScriptBlock {
        param(
            [String]$netCaptureLogPath,
            [String]$netCaptureLogSize,
            [String]$jobServerIp,
            [String]$netCpatureFilter
        )

        if (!(Test-Path -Path "$netCaptureLogPath")) {
            New-Item -ItemType Directory $netCaptureLogPath
        }
        $serverNetCaptureLogName = "$($netCaptureLogPath)$($env:COMPUTERNAME)_$($(Get-Date).ToString('yyyyMMddhhmmss')).cap"
        
        if([String]::IsNullOrEmpty($jobServerIp)) {
            $nmcapCommand = "`"c:\Program Files\Microsoft Network Monitor 3\nmcap.exe`" /network * /capture `"$netCpatureFilter`"  /file `"$($serverNetCaptureLogName)`":$netCaptureLogSize /DisableConversations /stopwhen /frame (icmp and ipv4.totallength==534)"
        } else {
            $nmcapCommand = "`"c:\Program Files\Microsoft Network Monitor 3\nmcap.exe`" /network * /capture `"$netCpatureFilter`"  /file `"$($serverNetCaptureLogName)`":$netCaptureLogSize /DisableConversations /stopwhen /frame (icmp and ipv4.totallength==534 and ipv4.address==$jobServerIp)"
        }
        cmd.exe /c $nmcapCommand
    } -ArgumentList $netCaptureLogPath, $netCaptureLogSize, $jobServerIp, $netCpatureFilter

    Return $jobs
}

function Stop-NetworkCapture
{
    param(
        [Parameter(Mandatory=$True)]
        [String[]]$servers
    )

    $servers | Foreach-object -Process{
        $pingCommand = "ping $_ -l 506 -4"
        cmd.exe /c $pingCommand
    }
}

function get-jobStatus
{
    param(
        [Parameter(Mandatory=$True)]
        [object]$jobs,
        [Parameter(Mandatory=$false)]
        [Switch]$createLogFile,
        [Parameter(Mandatory=$false)]
        [String]$jobLogfilePath
    )

    $output = (Get-date | Out-String -Width 2000)
    $message = ($jobs.ChildJobs | ft Id,Location,State,JobStatelnfo,@{l='errorCount';e={$_.error.Count}},@{l='WarningCount';e={$_.Warning.Count}},@{l='InformationCount'; e={$_.Information.Count}} | Out-String -Width 2000)
    Write-Host $message
    $output += "$message`n`n"
    
    $jobs.ChildJobs | foreach-Object -Process{
        # job info
        $message = ($_ | Format-Table Id,Location,State,StartDate,xxxx | Out-String -Width 2000)
        $output += "$message==================================`n`n"
        Write-Host "$message==================================`n"

        $message = ($_.Command | Out-String -Width 2000)
        $output += "$message`n"
        Write-Host "$message`n"

        # Error
        $message = "Error:"
        $output += "$message`n"
        $message = $_.Error | Out-String -Width 2000
        $output += "$message`n`n"
        Write-Host $message -ForegroundColor Red
        
        # Warning
        $message = "Warning:"
        $output += "$message`n"
        $message = $_.Warning | Out-String -Width 2000
        $output += "$message`n`n"
        Write-Host $message -ForegroundColor Yellow
    
        # Information
        $message = "Information:"
        $output += "$message`n"
        $message = $_.Information | Out-String -Width 2000
        $output += "$message`n`n"
        Write-Host $message -ForegroundColor Green
    }

    if($createLogFile) {
        Out-File -InputObject $output -FilePath $jobLogfilePath -Encoding utf8
    }

}

function Move-NetworkCaptureLogFile
{
    param(
        [Parameter(Mandatory=$True)]
        [String[]]$servers,
        [Parameter(Mandatory=$True)]
        [String]$srcPath,
        [Parameter(Mandatory=$True)]
        [String]$desPath
    )

    $servers | Foreach-object -Process{
        $pingCommand = "ping $_ -l 506 -4"
        cmd.exe /c $pingCommand
    }
}

Export-ModuleMember -Function Start-NetworkCapture
Export-ModuleMember -Function Stop-NetworkCapture
Export-ModuleMember -Function get-jobStatus
Export-ModuleMember -Function Move-NetworkCaptureLogFile

<#
#移除 windows 抓包的任务
#get-job|%{ $_|Remove-Job}
#将 windows 的抓包文件复制到本地
$windows|%{
    Copy-Item "\$_\c$\tmp.cap" "$capfolder\$_-$time.cap"
}
echo "Done: Net package

#>