<#
�н���̨Windows Active Directory����������Ҫʹ��powershell�ű�����佡��״̬��
�ƻ���powershell�ű��������ÿ̨Windows Active Directory�����������û������֤���롣�����֤ʧ�ܣ����������ļ��д�롰Failed��������¼�����֤��ʱ�������֤�ɹ��������������ļ���д�롰Success��������¼�����֤��ʱ��
ִ�еĽ�������ض�Ŀ¼�£�ÿ������һ���ļ���
��д�˸�powershell�ű�����������£���û���߼�����
#>
# ���ò���
$serversPath = "D:\HealthCheck\servers.txt" # ����AD�������嵥�ļ�
$credPath = "D:\HealthCheck\ad_monitor.cred" # ������Կ�ļ���Import-Clixml �����л��� PSCredential ������Ҫȷ������ͬ���û��ͻ��������ɣ�������ܻ�ʧ�ܡ������ǰ���ƾ���ļ��Ƿ��ڵ�ǰ�û����������ɡ�
$logDir = "D:\HealthCheck\Logs" # ������־�ļ�Ŀ¼
$global:TimeoutSeconds = 10 # ����ȫ�ֳ�ʱʱ��
# ���������б��ļ��Ƿ���ڣ��粻�ڽ��򱨴���Ϣ����Windows Server Application��־
if (-not (Test-Path $serversPath)) {
    Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Error -Message "Error: Cannot read servers file, Please Update $serversPath"
    exit 1
}
# �����־Ŀ¼�Ƿ����
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
# ������־�ļ�����ÿ��һ����
$logFile = Join-Path $logDir ("HealthCheck_{0:yyyyMMdd}.csv" -f (Get-Date))
# ��ʼ����־�ļ���ͷ��ÿ��һ�Σ�
if (-not (Test-Path $logFile)) {
    "Timestamp,Server,Status,LatencyMs,Error" | Out-File $logFile -Encoding UTF8 -Force
}
# ����ƾ�ݣ�����ѭ����һ���Ե��룬�����ƾ���Ƿ�����������ƾ�ݲ����ڣ����򱨴���Ϣ����Windows Server Application��־
try {
    $cred = Import-Clixml $credPath
} catch {
    Write-EventLog -LogName Application -Source "Application" -EventID 56002 -EntryType Error -Message "Error: Cannot read credential file, Please Update $credPath"
    exit 1
}

# ��ʱִ�к���
function Invoke-WithTimeout {
    param(
        [string]$Server,
        # Ҫ���ں����ڲ��������$server���ٽ�$server��Ϊ�������ݸ�Invoke-WithTimeout���������ֱ���ڽű���ͷ�������$server�������ã����ܵ��³�ʱ������Ϣ��û����ȷ�ķ��������ơ�
        [pscredential]$Credential,
        # ���� DirectoryEntry ����ʱ��ֱ��ʹ�� PSCredential ����� SecurePassword���ö������Ǽ��ܴ洢�ġ�
        [int]$TimeoutSeconds = 10
    )    
    $job = Start-Job -ScriptBlock {
        param($s, $c)
        # ����Ϊʲô����ʹ�á������� $s �͡������� $c ������ֱ��ʹ�á������� $server �͡������� $Credential��
        # ԭ����������롣�� Start-Job����ű����У�{ ... }����������һ���������������У�����̨��ҵ�У�,����ζ�Žű����޷�ֱ�ӷ����ⲿ�������� $server �� $Credential��������ͨ���������ݡ�
        # $server �� $Credential �����ű��еġ���������$s �� $c �ǽű����еĲ��������ڽ��մ����ű����ݹ�����ֵ�� ���нű��� Start-Jobʱ ��ͨ��ĩβ�Ĳ��� -ArgumentList ���������ݸ��ű��飬�ű����е� param($s, $c) ������ա� 
        # �������ݵ�ԭ��
        # ���ű��е� $Server �� $Credential����Щ�����������ű����������ж���ġ�
        # �ű����е� $s �� $c����Щ�������ڽű�����������ж���ģ�����ֻ�����ڽű����ڲ���
        # -ArgumentList�����ǽ����ű��еı������ݸ��ű����еĲ�����������  
        try {
            # LDAP������֤
            $de = New-Object DirectoryServices.DirectoryEntry(
                "LDAP://$s",
                $c.UserName,
                $c.GetNetworkCredential().Password
            )
            # ǿ�ƴ��������֤��# ��ΪDirectoryEntry�����ӿ����ӳ٣����߼�ʹƾ�ݴ���Ҳ���ܷ��ز�����Ϣ�����õķ�����ǿ����֤���������$de.RefreshCache()�����߳��Է���һ����Ҫ��֤�����ԣ����������������쳣��
            $de.RefreshCache()
            if (-not $de.psbase.Connected) { 
                 throw "Error: Connection failed on $s: $_.Exception.Message"
            }
            return $true
        } catch {
            throw "Error: LDAP failed on $s: $_.Exception.Message"
        }
    } -ArgumentList $Server, $Credential
    # ������ʱ����
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        do {
            if ($job.State -eq 'Completed') {
                return Receive-Job $job
            }
            Start-Sleep -Milliseconds 200
        } while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        
        throw "Error: Timeout after $TimeoutSeconds seconds on $Server"
    } finally {
        if ($job.State -ne 'Completed') { Stop-Job $job }
        Remove-Job $job -Force
    }
}
# ��ѭ�����������з�����������չ�����֤
foreach ($server in (Get-Content $serversPath)) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = "Success"
    $errorMsg = ""
    $latency = 0

    try {
        # ʹ�ü����Ը��ߵ�Ping���
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($server, 2000)
        if ($reply.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) {
            throw "Ping failed"
        }
        # ����ʱ�������֤
        $authResult = Invoke-WithTimeout -Server $server -Credential $cred -TimeoutSeconds $global:TimeoutSeconds
        # ��� LDAP ��֤�ɹ��������֤��Ϊ�ɹ������� $true��, �����û���׳��쳣������Ϊ�ɹ�
    } catch {
        $status = "Failed"
        $errorMsg = $_.Exception.Message
    } finally {
        if ($sw.IsRunning) { $sw.Stop() }
        $latency = $sw.ElapsedMilliseconds
        # ��try�����󣬲��ܳɹ���񣬶�ֹͣ$sw������catch���л�ȡ���ʱ
    }
    # ��¼���
    # ʹ�ö��󵼳�����������һ�����ݽṹΪ��ϣ��Ķ���
    # û�в��÷��ֶ�ƴ���ַ���������"$timestamp,$server,Success,$($sw.ElapsedMilliseconds)," | Out-File $logFile -Append�� �������������ַ�ʱ���綺�ŵȣ��������ʽ����
    [PSCustomObject]@{
        Timestamp = $timestamp
        Server    = $server
        Status    = $status
        LatencyMs = $latency
        Error     = $errorMsg
    } | Export-Csv $logFile -Append -NoTypeInformation -Encoding UTF8
}
