<#
日期：2020.05
用途：批量抓包脚本，支持windows和Linux。
先决条件：如涉及linux抓包，需要Linux上已安装tcpdump程序，并在本地执行机上安装powershell的posh-ssh.2.0.2模块。
流程说明：
1.先判断windows是否安装Net Monitor软件，如果没有安装，则远程安装。
2.调用windows的nmcap.exe和linux的tcpdump命令进行抓包。
3.等待$waittime秒。
4.停止linux的抓包命令（windows的抓包自动停止）。
5.将抓包文件复制到本地的$capfolder目录。

安装posh-ssh模块的方法：将posh-ssh目录复制到C:\Program Files\WindowsPowerShell\Modules目录里。

#>

#linux的IP地址
#$linux="10.190.4.226","10.190.4.229","10.190.4.230"
#windows的IP地址
$windows="poc01mux01","poc01mux02"
#本地抓包文件存放目录
$capfolder="c:\cap"
#抓包等待时间
$waittime=60
#本地Network Monitor安装程序位置
$nmonitor="c:\NM34_x64.exe"
#windows抓包文件最大的大小
$capfilesize="512M"
#Linux虚拟机的密码
#$pw=ConvertTo-SecureString -String "!QAZ2wsx" -AsPlainText -Force
#$user="root"
#$cred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pw

$time=get-date -Format MMddHHmm

# job log output function
function write-mlog {
    param(
        [String] $filePath,
        [Object] $Massage,
        [Switch] $Append=$false
    )
    if ($Append) {
        Out-File -FilePath $filePath -Width 1000 -InputObject ($Massage) -Encoding utf8 -Append 
    } else {
        Out-File -FilePath $filePath -Width 1000 -InputObject ($Massage) -Encoding utf8
    }
}

<#$linuxsessions=@()
$linuxhostname=@{}
#用于抓包文件的名称
$time=get-date -Format MMddHHmm
#Linux tcpdump抓包启动和停止的命令
$starttcpdump="tcpdump -w tmp.cap > /dev/null 2>&1  &"
$stoptcpdump='let id=$(ps -ef|grep tcpdump|grep -v grep|awk ''{print $2}'');kill $id'
#>

#检查windows是否安装了Network Monitor,如果没有安装，将安装文件复制过去
echo "start : check whether Network Monitor is installed. "
$notinstallnm=@()
$windows|%{
    if( !(icm $_ { Test-Path "C:\Program Files\Microsoft Network Monitor 3" }) ){
        Copy-Item $nmonitor "\\$_\c$" 
        $notinstallnm+=$_
    }
}
#对没有安装Network Monitor的windows执行安装命令
if( $notinstallnm ){

    echo "Network Monitor will be installed in $notinstallnm."

    $job=icm $notinstallnm -AsJob { cmd /c c:\NM34_x64.exe /Q }
    while( $job.State -ne "Completed" ){ sleep 3 }
}
echo "done : check whether Network Monitor is installed. "
<#
#对linux创建ssh连接，记录session id和hostname
$linux|%{
    $session=New-SSHSession -ComputerName $_ -Credential $cred -KeepAliveInterval 60 -AcceptKey
    $linuxsessions+=$session.SessionId
    $linuxhostname[$_]=(Invoke-SSHCommand -SessionId $session.SessionId -Command "hostname").output
}
#对linux启动网络抓包
#Invoke-SSHCommand -Sessionid $linuxsessions  -Command $starttcpdump
#>

#对windows启动网络抓包

$job=icm $windows -AsJob -ArgumentList $capfilesize,$waittime {
    param([string]$capfilesize,[string]$waittime)

    if( Test-Path "c:\tmp.cap" ) { remove-item "c:\tmp.cap" }

    # cmd /c "C:\Program Files\Microsoft Network Monitor 3\nmcap.exe" /network * /capture  "tcp.port == 445" /File "c:\tmp.cap:$capfilesize" /stopwhen /timeafter $waittime
    $command = "`"C:\Program Files\Microsoft Network Monitor 3\NMCap.exe`" /network * /capture `"tcp.port == 445 && IPv4.Address == 10.145.129.15`" /File `"c:\tmp.cap:$capfilesize`" /startwhen /timeafter 1 /stopwhen /timeafter $waittime"
    cmd /c $command
}

echo "start : Net Package Capture."

sleep $waittime

echo "stopping : Net Package Capture."
<##对Linux停止网络抓包
Invoke-SSHCommand -Sessionid $linuxsessions   -Command $stoptcpdump

if( !(Test-Path $capfolder) ){ New-Item -ItemType dir -Name $capfolder }

将linux的抓包文件复制到本地
$linux|%{
    $hostname=$linuxhostname[$_]
    Get-SCPFile -ComputerName $_ -LocalFile "$capfolder\$hostname-$time.cap" -RemoteFile "tmp.cap" -Credential $cred
}
#关闭与linux的ssh连接
Remove-SSHSession -SessionId $linuxsessions
#>

#等待windows抓包结束
$logFilePath = "$capfolder\nmcap-$($time).log"
while($job.State -ne "Completed") {
    sleep 20
    # output resoult to c:\cap
    write-mlog -filePath $logFilePath -Massage ("Start tracking****************************** $time `n")
    Foreach ($oneJob in $job.ChildJobs) {
        write-mlog -filePath $logFilePath -Massage ($oneJob.Location + " | Start: " + $oneJob.PSBeginTime + " ==========================================`n") -Append
        # error
        write-mlog -filePath $logFilePath -Massage ($oneJob.Location + "[Error...]") -Append
        write-mlog -filePath $logFilePath -Massage ($oneJob.Error) -Append
        write-mlog -filePath $logFilePath -Massage ("") -Append

        # warning
        write-mlog -filePath $logFilePath -Massage ($oneJob.Location + "[Warning...]") -Append
        write-mlog -filePath $logFilePath -Massage ($oneJob.Warning) -Append
        write-mlog -filePath $logFilePath -Massage ("") -Append

        # info
        write-mlog -filePath $logFilePath -Massage ($oneJob.Location + "[Information...]") -Append
        write-mlog -filePath $logFilePath -Massage ($oneJob.Information) -Append
        write-mlog -filePath $logFilePath -Massage ("") -Append

        # output
        write-mlog -filePath $logFilePath -Massage ($oneJob.Location + "[Output...]") -Append
        write-mlog -filePath $logFilePath -Massage ($oneJob.Output) -Append
        write-mlog -filePath $logFilePath -Massage ("") -Append

        write-mlog -filePath $logFilePath -Massage ($oneJob.Location + " | End: " + $oneJob.PSEndTime + " ===================================") -Append
        write-mlog -filePath $logFilePath -Massage ("`n `n") -Append
    }
}
#移除windows抓包的任务
    #get-job|%{ $_|Remove-Job}
#将windows的抓包文件复制到本地
$windows|%{
    Copy-Item "\\$_\c$\tmp.cap" "$capfolder\$_-$time.cap"
}

echo "Done : Net package Capture."