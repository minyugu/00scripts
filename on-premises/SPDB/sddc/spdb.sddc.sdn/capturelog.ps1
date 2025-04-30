$scriptPath = $PSScriptRoot
Import-Module  "$scriptPath\spdb.troubleshooting\Module\spdb.sddc.captureNetwork.psm1" -Force

$servers = @("","")
$netCpatureFilter = "tcp.port == 3389 && IPv4.Address == 10.145.129.15"
$jobServerIp = "98.76.54.32"

$netCaptureLogPath = "c:\ms_capture\netmon\"
$netCaptureLogSize = "3000M"

<#

# start capture
$jobs = Start-NetworkCapture -servers $servers -netCpatureFilter $netCpatureFilter -netCaptureLogPath $netCaptureLogPath -netCaptureLogSize $netCaptureLogSize -jobServerIp $jobServerIp

# get job status
get-jobStatus -jobs $jobs -createLogFile -jobLogfilePath "$scriptPath\jobStatus.log"

# stop capture
Stop-NetworkCapture -servers $servers

#>







<# 通过 Schedule task 收数据包

md c:\newcallNetmon20240926
"c:\Program Files\Microsoft Network Monitor 3\nmcap.exe" /network * /capture "tcp.port == 8103"  /file "c:\newcallNetmon20240926\netmoncap1.cap:3000M" /DisableConversations /stopwhen /frame (icmp and ipv4.totallength==535)

ping 192.168.1.1 -l 507 -4

#>