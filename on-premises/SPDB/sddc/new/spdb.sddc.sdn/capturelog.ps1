$scriptPath = $PSScriptRoot
Import-Module  "$scriptPath\spdb.troubleshooting\Module\spdb.sddc.captureNetwork.psm1" -Force
Set-Location -Path $scriptPath

######### NetMon ���������޸����±��� ######

# ץ��·���ķ�����
$servers = @("poc04mux02","poc04nc05")
# �������������
$netCpatureFilter = "tcp.port == 3389"
# ������ļ���С
$netCaptureLogSize = "3000M"

# �������ŵ�λ�ã����أ�
$netCaptureLogPath = "c:\ms_capture\netmon"
# �������������������λ�ã����ģ�
$netCaptureLogPathOnServer = "$scriptPath\Logs\NetMonCaps"


######### SDN Trace ���������޸����±��� ######
# DIP VM���ڵ�Host
$sdnHost = @("AZ-POC04-WC001","AZ-POC04-WC002")
# ��һһ̨NC������
$ncVM = "poc04nc05"

#SDN Trace ��ŵ�·��
$SDNTraceOutputPath = "$scriptPath\Logs\SDNTrace"


######## ==========����ץ��==========
######## ==========���²��谴��Ҫ��ִ��==========
<#

# 1. ��ʼ����ץ��
$jobs = Start-NetworkCapture -servers $servers -netCpatureFilter $netCpatureFilter -netCaptureLogPath $netCaptureLogPath -netCaptureLogSize $netCaptureLogSize #-jobServerIp $jobServerIp

# 2[���]. �鿴ץ��job��״̬ - ȷ��Job�Ƿ�ʼִ�У��Ƿ��б���
get-jobStatus -jobs $jobs -createLogFile -jobLogfilePath "$scriptPath\jobStatus.log"

# ---------------------------------
# 4. ��������
# ---------------------------------

# 5. ֹͣ����ץ��
Stop-NetworkCapture -servers $servers

# 6[���]. �ٴο�ץ��job��״̬ -ȷ��Job�Ƿ���ɣ��Ƿ��б���
get-jobStatus -jobs $jobs -createLogFile -jobLogfilePath "$scriptPath\jobStatus.log"

# 9[���]. ���ٴο�ץ��job��״̬ -ȷ��Job�Ƿ���ɣ��Ƿ��б���
get-jobStatus -jobs $jobs -createLogFile -jobLogfilePath "$scriptPath\jobStatus.log"

# 10[���].�鿴ץ���ļ� - �Ƿ�����
$servers| ForEach-Object -Process {Get-ChildItem -Path "\\$_\$($netCaptureLogPath.Replace(':\','$\'))"} | ft FullName,Length,LastWriteTime

# 11.����������ļ�
Copy-NetworkCaptureLogFile -servers $servers -srcPath $netCaptureLogPath.Replace(":\","$\") -desPath $netCaptureLogPathOnServer

# 12[���].�鿴���ƺ��������ļ� - �Ƿ�����
Get-ChildItem -Path $netCaptureLogPathOnServer

# 13.�������������ļ�
Clear-NetworkCaptureLogFile -servers $servers -logPath $netCaptureLogPath.Replace(":\","$\")

#>

######## ==========SDN Trace==========
######## ==========���²��谴��Ҫ��ִ��==========

<#

# 3. ���� SDN MUX Trace
& "$scriptPath\spdb.troubleshooting\spdb.sddc.sdnTrace.ps1" -op "start" -ncVM $ncVM -sdnHosts $sdnHost -OutputPath $SDNTraceOutputPath

# 7. ֹͣ SDN MUX Trace
& "$scriptPath\spdb.troubleshooting\spdb.sddc.sdnTrace.ps1" -op "stop" -ncVM $ncVM -sdnHosts $sdnHost -OutputPath $SDNTraceOutputPath

# 8[���]. �鿴Trace�ļ�
Get-ChildItem -Path $SDNTraceOutputPath
#>














<# capture net package via Schedule task

md c:\newcallNetmon20240926
"c:\Program Files\Microsoft Network Monitor 3\nmcap.exe" /network * /capture "tcp.port == 8103"  /file "c:\newcallNetmon20240926\netmoncap1.cap:3000M" /DisableConversations /stopwhen /frame (icmp and ipv4.totallength==535)

ping 192.168.1.1 -l 507 -4


$waittime = 60
"c:\Program Files\Microsoft Network Monitor 3\nmcap.exe" /network * /capture "tcp.port == 8103"  /file "c:\newcallNetmon20240926\netmoncap1.cap:3000M" /DisableConversations /startwhen /timeafter 1 /stopwhen /timeafter $waittime
#>