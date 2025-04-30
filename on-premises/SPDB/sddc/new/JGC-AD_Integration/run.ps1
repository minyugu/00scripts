Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
Import-Module .\Get-DNSDebugLog.ps1 -Force

(Get-ChildItem -Path ".\logs\" -File).FullName | ForEach-Object -Process {
    Start-Job -ScriptBlock {
        Param($log,$scriptPath)
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
        Import-Module "$($scriptPath)\Get-DNSDebugLog.ps1" -Force
        Get-DNSDebugLog -DNSLog $log -RemoveDuplicateProperty Client | Export-Csv -Path "$($log).csv" -NoTypeInformation
    } -ArgumentList $_,((Get-Item .).FullName)
}

Get-Job
((Get-Job).ChildJobs) | select Id,Error,State,PSBeginTime,PSEndTime | ft


#########################################
workflow parallelProcessLog
{
    $logFiles = (Get-ChildItem -Path ".\logs\").FullName

    foreach -Parallel ($log in $logFiles)
    {
        Get-DNSDebugLog -DNSLog $log -RemoveDuplicateProperty Client #| Export-Csv -Path "$($log).csv"
    }
}   

#################################################
Import-Module .\Get-DNSDebugLog.ps1 -Force
$logFiles = (Get-ChildItem -Path ".\logs\").FullName | ForEach-Object -ThrottleLimit 3 -AsJob -Parallel {
    Get-DNSDebugLog -DNSLog $_ -RemoveDuplicateProperty Client | Export-Csv -Path "$($log).csv"
}

###################################################
