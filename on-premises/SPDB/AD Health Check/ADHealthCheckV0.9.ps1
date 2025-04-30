<#
有近百台Windows Active Directory服务器，需要使用powershell脚本监控其健康状态。
计划在powershell脚本里，轮流向每台Windows Active Directory服务器发起用户身份认证申请。如果认证失败，则向检查结果文件里，写入“Failed”，并记录身份认证耗时；如果认证成功给，则向检查结果文件里写入“Success”，并记录身份认证耗时。
执行的结果，在特定目录下，每天生成一个文件。
我写了个powershell脚本，请您检查下，有没有逻辑错误。
#>
# 配置参数
$serversPath = "D:\HealthCheck\servers.txt" # 设置AD服务器清单文件
$credPath = "D:\HealthCheck\ad_monitor.cred" # 定义密钥文件，Import-Clixml 反序列化的 PSCredential 对象需要确保在相同的用户和机器上生成，否则解密会失败。务必提前检查凭据文件是否在当前用户上下文生成。
$logDir = "D:\HealthCheck\Logs" # 设置日志文件目录
$global:TimeoutSeconds = 10 # 设置全局超时时间
# 检查服务器列表文件是否存在，如不在将则报错信息发到Windows Server Application日志
if (-not (Test-Path $serversPath)) {
    Write-EventLog -LogName Application -Source "Application" -EventID 56001 -EntryType Error -Message "Error: Cannot read servers file, Please Update $serversPath"
    exit 1
}
# 检查日志目录是否存在
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
# 生成日志文件名（每日一个）
$logFile = Join-Path $logDir ("HealthCheck_{0:yyyyMMdd}.csv" -f (Get-Date))
# 初始化日志文件表头（每日一次）
if (-not (Test-Path $logFile)) {
    "Timestamp,Server,Status,LatencyMs,Error" | Out-File $logFile -Encoding UTF8 -Force
}
# 导入凭据（在主循环外一次性导入，并检查凭据是否正常），如凭据不存在，将则报错信息发到Windows Server Application日志
try {
    $cred = Import-Clixml $credPath
} catch {
    Write-EventLog -LogName Application -Source "Application" -EventID 56002 -EntryType Error -Message "Error: Cannot read credential file, Please Update $credPath"
    exit 1
}

# 超时执行函数
function Invoke-WithTimeout {
    param(
        [string]$Server,
        # 要先在函数内部定义变量$server，再将$server作为参数传递给Invoke-WithTimeout函数。如果直接在脚本开头定义变量$server，再引用，可能导致超时错误信息中没有正确的服务器名称。
        [pscredential]$Credential,
        # 创建 DirectoryEntry 对象时，直接使用 PSCredential 对象的 SecurePassword，该对象本身是加密存储的。
        [int]$TimeoutSeconds = 10
    )    
    $job = Start-Job -ScriptBlock {
        param($s, $c)
        # 这里为什么单独使用“参数” $s 和“参数” $c 而不是直接使用“变量” $server 和“变量” $Credential？
        # 原因：作用域隔离。在 Start-Job这个脚本块中（{ ... }）会运行在一个独立的上下文中（即后台作业中）,这意味着脚本块无法直接访问外部变量（如 $server 和 $Credential），除非通过参数传递。
        # $server 和 $Credential 是主脚本中的“变量”。$s 和 $c 是脚本块中的参数，用于接收从主脚本传递过来的值。 运行脚本块 Start-Job时 ，通过末尾的参数 -ArgumentList 将参数传递给脚本块，脚本块中的 param($s, $c) 负责接收。 
        # 参数传递的原理：
        # 主脚本中的 $Server 和 $Credential：这些变量是在主脚本的作用域中定义的。
        # 脚本块中的 $s 和 $c：这些参数是在脚本块的作用域中定义的，它们只存在于脚本块内部。
        # -ArgumentList：这是将主脚本中的变量传递给脚本块中的参数的桥梁。  
        try {
            # LDAP连接验证
            $de = New-Object DirectoryServices.DirectoryEntry(
                "LDAP://$s",
                $c.UserName,
                $c.GetNetworkCredential().Password
            )
            # 强制触发身份验证，# 因为DirectoryEntry的连接可能延迟，或者即使凭据错误，也可能返回部分信息。更好的方法是强制验证，比如调用$de.RefreshCache()，或者尝试访问一个需要认证的属性，这样会立即触发异常。
            $de.RefreshCache()
            if (-not $de.psbase.Connected) { 
                 throw "Error: Connection failed on $s: $_.Exception.Message"
            }
            return $true
        } catch {
            throw "Error: LDAP failed on $s: $_.Exception.Message"
        }
    } -ArgumentList $Server, $Credential
    # 启动超时控制
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
# 主循环，遍历所有服务器，并开展身份认证
foreach ($server in (Get-Content $serversPath)) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = "Success"
    $errorMsg = ""
    $latency = 0

    try {
        # 使用兼容性更高的Ping检查
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($server, 2000)
        if ($reply.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) {
            throw "Ping failed"
        }
        # 带超时的身份验证
        $authResult = Invoke-WithTimeout -Server $server -Credential $cred -TimeoutSeconds $global:TimeoutSeconds
        # 如果 LDAP 验证成功，身份认证视为成功（返回 $true）, 但如果没有抛出异常，就认为成功
    } catch {
        $status = "Failed"
        $errorMsg = $_.Exception.Message
    } finally {
        if ($sw.IsRunning) { $sw.Stop() }
        $latency = $sw.ElapsedMilliseconds
        # 在try块的最后，不管成功与否，都停止$sw，并在catch块中获取其耗时
    }
    # 记录结果
    # 使用对象导出方法，创建一个数据结构为哈希表的对象。
    # 没有采用非手动拼接字符法，比如"$timestamp,$server,Success,$($sw.ElapsedMilliseconds)," | Out-File $logFile -Append， 后者遇到特殊字符时（如逗号等）会引起格式错误。
    [PSCustomObject]@{
        Timestamp = $timestamp
        Server    = $server
        Status    = $status
        LatencyMs = $latency
        Error     = $errorMsg
    } | Export-Csv $logFile -Append -NoTypeInformation -Encoding UTF8
}
