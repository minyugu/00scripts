$scriptPath = $PSScriptRoot
Import-Module  "$scriptPath\spdb.troubleshooting\Module\spdb.sddc.captureNetwork.psm1" -Force
Set-Location -Path $scriptPath

######### NetMon 根据需求修改以下变量 ######

# 抓网路包的服务器
$servers = @("poc04mux02","poc04nc05")
# 网络包过滤条件
$netCpatureFilter = "tcp.port == 3389"
# 网络包文件大小
$netCaptureLogSize = "3000M"

# 网络包存放的位置（本地）
$netCaptureLogPath = "c:\ms_capture\netmon"
# 网络包拷贝至服务器的位置（中心）
$netCaptureLogPathOnServer = "$scriptPath\Logs\NetMonCaps"


######### SDN Trace 根据需求修改以下变量 ######
# DIP VM所在的Host
$sdnHost = @("AZ-POC04-WC001","AZ-POC04-WC002")
# 任一一台NC服务器
$ncVM = "poc04nc05"

#SDN Trace 存放的路径
$SDNTraceOutputPath = "$scriptPath\Logs\SDNTrace"


######## ==========网络抓包==========
######## ==========以下步骤按需要逐步执行==========
<#

# 1. 开始网络抓包
$jobs = Start-NetworkCapture -servers $servers -netCpatureFilter $netCpatureFilter -netCaptureLogPath $netCaptureLogPath -netCaptureLogSize $netCaptureLogSize #-jobServerIp $jobServerIp

# 2[检查]. 查看抓包job的状态 - 确认Job是否开始执行，是否有报错
get-jobStatus -jobs $jobs -createLogFile -jobLogfilePath "$scriptPath\jobStatus.log"

# ---------------------------------
# 4. 复现问题
# ---------------------------------

# 5. 停止网络抓包
Stop-NetworkCapture -servers $servers

# 6[检查]. 再次看抓包job的状态 -确认Job是否完成，是否有报错
get-jobStatus -jobs $jobs -createLogFile -jobLogfilePath "$scriptPath\jobStatus.log"

# 9[检查]. 再再次看抓包job的状态 -确认Job是否完成，是否有报错
get-jobStatus -jobs $jobs -createLogFile -jobLogfilePath "$scriptPath\jobStatus.log"

# 10[检查].查看抓包文件 - 是否生成
$servers| ForEach-Object -Process {Get-ChildItem -Path "\\$_\$($netCaptureLogPath.Replace(':\','$\'))"} | ft FullName,Length,LastWriteTime

# 11.复制网络包文件
Copy-NetworkCaptureLogFile -servers $servers -srcPath $netCaptureLogPath.Replace(":\","$\") -desPath $netCaptureLogPathOnServer

# 12[检查].查看复制后的网络包文件 - 是否生成
Get-ChildItem -Path $netCaptureLogPathOnServer

# 13.清除本地网络包文件
Clear-NetworkCaptureLogFile -servers $servers -logPath $netCaptureLogPath.Replace(":\","$\")

#>

######## ==========SDN Trace==========
######## ==========以下步骤按需要逐步执行==========

<#

# 3. 启动 SDN MUX Trace
& "$scriptPath\spdb.troubleshooting\spdb.sddc.sdnTrace.ps1" -op "start" -ncVM $ncVM -sdnHosts $sdnHost -OutputPath $SDNTraceOutputPath

# 7. 停止 SDN MUX Trace
& "$scriptPath\spdb.troubleshooting\spdb.sddc.sdnTrace.ps1" -op "stop" -ncVM $ncVM -sdnHosts $sdnHost -OutputPath $SDNTraceOutputPath

# 8[检查]. 查看Trace文件
Get-ChildItem -Path $SDNTraceOutputPath
#>














<# capture net package via Schedule task

md c:\newcallNetmon20240926
"c:\Program Files\Microsoft Network Monitor 3\nmcap.exe" /network * /capture "tcp.port == 8103"  /file "c:\newcallNetmon20240926\netmoncap1.cap:3000M" /DisableConversations /stopwhen /frame (icmp and ipv4.totallength==535)

ping 192.168.1.1 -l 507 -4


$waittime = 60
"c:\Program Files\Microsoft Network Monitor 3\nmcap.exe" /network * /capture "tcp.port == 8103"  /file "c:\newcallNetmon20240926\netmoncap1.cap:3000M" /DisableConversations /startwhen /timeafter 1 /stopwhen /timeafter $waittime
#>