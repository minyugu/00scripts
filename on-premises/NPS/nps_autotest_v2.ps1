<#
.NOTES
    Name: NPS策略自动添加工具（拒绝策略-PEAP，定时禁用）
    Version: 1.0
    Author: linzhengtao
    Last Updated: 2025-01
#>
<# 1.1 xml格式校验，注意插入的节点是Microsoft_Internet_Authentication_Service name="Microsoft_Internet_Authentication_Service">测试服务器RadiusProfiles 下的 Children 节点和NetworkPolicy的位置
且需要校验，优先级跟手动插入的不一样最高级都为1，脚本生成的是1，策略允许也是1，怎么判断和添加的上限？？有没有办法修改以循环遍历的方法顺序添加。。。
脚本中固定插入到最上面优先级自动判定为1，拒绝策略全部为1怎么判断，规模测试上限？？是不是像ACL一样。。。
1.2 子策略禁用需要定位到$ns.AddNamespace("dt", "urn:schemas-microsoft-com:datatypes") （<Policy_Enabled dt:dt="boolean" xmlns:dt="urn:schemas-microsoft-com:datatypes">1</Policy_Enabled> ）且需要用beyondcompare 对比格式，否则容易导致找不到策略
1.3 定时任务的触发的时间需要按照当前时间去+触发时间去做任务运行的时间
#>  
$MacAddress = Read-Host "请输入 Calling-Station-ID（MAC地址，例如 2233-4455-6677）"
$UnlockHours = Read-Host "请输入解锁时长（小时）"
$TimeoutSeconds = [int]$UnlockHours * 3600
$rawMAC = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToLower() #正则和转换小写
if ($rawMAC.Length -ne 12) {
    Write-Error "MAC地址格式错误，请检查输入"
    exit 1
}
$cleanMAC = $rawMAC.Substring(0,4) + "-" + $rawMAC.Substring(4,4) + "-" + $rawMAC.Substring(8,4)
# 生成策略名称（附加时间戳以保证唯一性）
$policyNameNew = "拒绝MAC_$cleanMAC_$(Get-Date -Format 'yyyyMMddHHmmss')"
#endregion

#region 全局配置（备份 log ）
$NPSConfigPath = "C:\Windows\System32\ias\ias.xml"
$BackupDir = "C:\NPS_Backup"
$BackupPath = "$BackupDir\ias_$(Get-Date -Format 'yyyyMMddHHmmss').xml"
$LogDir = "$BackupDir\Logs"
$TranscriptLog = "$LogDir\Operation_$(Get-Date -Format 'yyyyMMddHHmmss').log"

@($BackupDir, $LogDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
}

Start-Transcript -Path $TranscriptLog -Append
#endregion

#region 权限控制是否需要修改待优化
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "必须使用管理员权限运行！"
    Stop-Transcript
    exit 1
}

#配置文件的权限获取
try {
    takeown /f $NPSConfigPath /A 2>&1 | Out-Null
    icacls $NPSConfigPath /grant "Administrators:F" /T /C 2>&1 | Out-Null
}
catch {
    Write-Error "文件权限获取失败: $_"
    Stop-Transcript
    exit 1
}
#endregion

#region 服务控制（本脚本不再停止/重启IAS服务）待后续微软确认另外添加策略的上限！
# 此处不执行停止或重启IAS服务操作
#endregion

#region 配置备份
try {
    Write-Host "[+] 创建配置备份..."
    Copy-Item $NPSConfigPath $BackupPath -Force
    if (-not (Test-Path $BackupPath)) { throw "备份文件未创建" }
    [xml]::new().Load($BackupPath) | Out-Null
}
catch {
    Write-Error "备份失败: $_"
    Stop-Transcript
    exit 1
}
#endregion

#region XML配置处理 - 插入拒绝策按照测试模板
try {
    Write-Host "[+] 加载XML配置..."
    [xml]$NPSConfig = Get-Content -Path $NPSConfigPath -Raw -Encoding UTF8
    $ns = New-Object System.Xml.XmlNamespaceManager($NPSConfig.NameTable)
    $ns.AddNamespace("dt", "urn:schemas-microsoft-com:datatypes")
    
    # 定位 测试服务器RadiusProfiles 下的 Children 节点
    $radiusXPath = "/Root/Children/Microsoft_Internet_Authentication_Service/Children/RadiusProfiles/Children"
    $radiusContainer = $NPSConfig.SelectSingleNode($radiusXPath, $ns)
    if (-not $radiusContainer) { throw "未找到 RadiusProfiles 的 Children 节点" }
    
    # 定位 测试服务器NetworkPolicy 下的 Children 节点
    $networkXPath = "/Root/Children/Microsoft_Internet_Authentication_Service/Children/NetworkPolicy/Children"
    $networkContainer = $NPSConfig.SelectSingleNode($networkXPath, $ns)
    if (-not $networkContainer) { throw "未找到 NetworkPolicy 的 Children 节点" }
    
####[mg]####
#region [mg] find the network policy with specific mac
    $macExisted = $false
    $networkPolicys = $NPSConfig.SelectNodes($networkXPath)
    foreach ($networkPolicy in $networkPolicys) {
        foreach ($npEnum in $networkPolicy.GetEnumerator() ) {
            $npEnum.GetElementsByTagName("msNPConstraint") | Where-Object { $null -ne $_ } | ForEach-Object {
                if ($_.InnerText.trim() -eq "MATCH(`"Calling-Station-Id=$cleanMAC`")") {
                    $npEnum.GetElementsByTagName("Policy_Enabled") | Where-Object { $null -ne $_ } | ForEach-Object {
                        # enable policy
                        if ($_.InnerText.trim() -eq "0") {
                            $_.InnerText = "1"
                        }
                    }
                    $macExisted = $true
                    break
                }
            }
        }
    }
#endregion

####[mg]####
    # check if the mac address not exists in the configuration then add the new policy
    if ($macExisted -eq $false) {
        # 构造 RadiusProfiles 模板（含PEAP配置）需要设置身份验证方法为EAP
        $radiusTemplate = @"
<Test_deny name="$policyNameNew">
    <Properties>
        <IP_Filter_Template_Guid xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="string">{00000000-0000-0000-0000-000000000000}</IP_Filter_Template_Guid>
        <Opaque_Data xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="string"></Opaque_Data>
        <Template_Guid xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="string">{00000000-0000-0000-0000-000000000000}</Template_Guid>
        <msEAPConfiguration xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="bin.hex">
1900000000000000000000000000000038000000020000003800000001000000140000002c6309139f605edd59adf035b1fff11ee18df5ac0100000001000000100000001a00000000000000
        </msEAPConfiguration>
        <msNPAllowDialin xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="boolean">0</msNPAllowDialin>
        <msNPAllowedEapType xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="bin.hex">
19000000000000000000000000000000
        </msNPAllowedEapType>
        <msNPAuthenticationType2 xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">5</msNPAuthenticationType2>
        <msNPAuthenticationType2 xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">3</msNPAuthenticationType2>
        <msNPAuthenticationType2 xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">9</msNPAuthenticationType2>
        <msNPAuthenticationType2 xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">4</msNPAuthenticationType2>
        <msNPAuthenticationType2 xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">10</msNPAuthenticationType2>
        <msRADIUSFramedProtocol xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">1</msRADIUSFramedProtocol>
        <msRADIUSServiceType xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">2</msRADIUSServiceType>
    </Properties>
</Test_deny>
"@

####[mg]####
        #region find the maximum value of msNPSequence in an XML file to increment the sequence number of network policy
        $lastSequence = $NPSConfig.SelectNodes($networkXPath) | 
            ForEach-Object { $_.GetElementsByTagName("msNPSequence") } |
            Where-Object { $_ -ne $null } |
            ForEach-Object { [int]$_.InnerText } |
            Measure-Object -Maximum
        #endregion

        # 构造 NetworkPolicy 模板（含Policy_Enabled属性并设置参数后续需要通过这个参数设置定时任务中的禁用策略）优化：删除不做禁用??
####[mg]#### add sequence number to the network policy template
        $networkTemplate = @"
<Test_deny name="$policyNameNew">
    <Properties>
        <Opaque_Data xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="string"></Opaque_Data>
        <Policy_Enabled xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="boolean">1</Policy_Enabled>
        <Policy_SourceTag xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">0</Policy_SourceTag>
        <Template_Guid xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="string">{00000000-0000-0000-0000-000000000000}</Template_Guid>
        <msNPAction xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="string">Test-deny</msNPAction>
        <msNPConstraint xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="string">
            MATCH("Calling-Station-Id=$cleanMAC")
        </msNPConstraint>
        <msNPSequence xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="int">$($lastSequence.Maximum+1)</msNPSequence>
    </Properties>
</Test_deny>
"@
        
        # 将两个模板转换为XML节点
        $radiusFragment = $NPSConfig.CreateDocumentFragment()
        $radiusFragment.InnerXml = $radiusTemplate
        $networkFragment = $NPSConfig.CreateDocumentFragment()
        $networkFragment.InnerXml = $networkTemplate
        
        # 分别插入到对应容器的首位(正式环境中是否一致，需要考虑的点是插在最上面且优先级设置为1是否拒绝策略都会生效，是否需要手动移动，因为手动添加的策略是有顺序的，这里是代码中强制固定)
        $radiusContainer.InsertBefore($radiusFragment, $radiusContainer.FirstChild) | Out-Null
        $networkContainer.InsertBefore($networkFragment, $networkContainer.FirstChild) | Out-Null
    }
    
    # 保存到临时文件并验证XML格式
    $tempFile = "$NPSConfigPath.tmp"
    $NPSConfig.Save($tempFile)
    $validator = New-Object System.Xml.XmlDocument
    $validator.PreserveWhitespace = $true
    $validator.Load($tempFile)
    if (-not $validator.SelectSingleNode("//Test_deny[@name='$policyNameNew']")) {
        throw "新策略节点验证失败"
    }
    Move-Item $tempFile $NPSConfigPath -Force
}
catch {
    Write-Error "[!] XML处理失败: $_"
    Copy-Item $BackupPath $NPSConfigPath -Force #处理失败，强制回滚原来配置
    Stop-Transcript
    exit 1
}
#endregion

#region 配置导入
try {
    Write-Host "[+] 导入新配置..."
    $importResult = netsh nps import filename="$NPSConfigPath" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "导入失败: $importResult" }
    Write-Host "[√] 配置导入成功"
}
catch {
    Write-Error "[!] 导入失败: $_"
    Copy-Item $BackupPath $NPSConfigPath -Force
    netsh nps import filename="$NPSConfigPath"
    Stop-Transcript
    exit 1
}
#endregion

#region 生成解除策略的子脚本（禁用策略，将 Policy_Enabled 的值改为 0）注意需要非空检验#注意需要严格找到xml禁用的位置
$removeScriptPath = "$BackupDir\RemovePolicy_$cleanMAC.ps1"
$removeScript = @"
param([string]`$MacAddress)
Start-Transcript -Path "C:\NPS_Backup\Logs\Remove_${cleanMAC}_$(Get-Date -Format 'yyyyMMddHHmmss').log" -Append
[xml]`$config = Get-Content -Path "C:\Windows\System32\ias\ias.xml" -Raw -Encoding UTF8
`$ns = New-Object System.Xml.XmlNamespaceManager(`$config.NameTable)
`$ns.AddNamespace("dt", "urn:schemas-microsoft-com:datatypes")
`$enabledNode = `$config.SelectSingleNode("//NetworkPolicy/Children/Test_deny[@name='$policyNameNew']/Properties/Policy_Enabled", `$ns)
if (`$enabledNode -ne `$null) {
    `$enabledNode.InnerText = "0"
    `$config.Save("C:\NPS_Backup\NPSConfigModified_${cleanMAC}.xml")
    netsh nps import filename="C:\NPS_Backup\NPSConfigModified_${cleanMAC}.xml"
    Write-Host "策略已禁用"
}
else {
    Write-Host "未找到目标策略的 Policy_Enabled 节点，无需操作"
}
Stop-Transcript
"@
Set-Content -Path $removeScriptPath -Value $removeScript -Encoding UTF8
#endregion


#region 创建计划任务以定时禁用策略
# 计算任务触发时间：当前时间 + 用户输入的解锁时长（小时）
$triggerTime = (Get-Date).AddHours($UnlockHours)
$taskName = "NPS_Unlock_${cleanMAC}_$(Get-Date -Format 'yyyyMMddHHmmss')"

# 构造任务参数字符串，包含 -NoProfile 参数确保简洁运行
$arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$removeScriptPath`" -MacAddress `"$MacAddress`""
Write-Debug "任务参数: $arguments"

$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
$taskTrigger = New-ScheduledTaskTrigger -Once -At $triggerTime
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal | Out-Null  #下一次运行时间
Write-Host "[+] 计划任务 [$taskName] 已创建，将在 $triggerTime 自动禁用策略"
#endregion

#region 验证提示（需要改成自动验证，频繁读取？？）
Write-Host "`n[验证步骤]"
Write-Host "1. 查看策略: netsh nps show config | findstr /i `"$policyNameNew`""
Write-Host "2. 检查任务: schtasks /query /tn `"$taskName`""
Write-Host "3. 服务状态: Get-Service IAS"
#endregion

Stop-Transcript #

#注意要插入的节点和转换的格式Microsoft_Internet_Authentication_Service name="Microsoft_Internet_Authentication_Service">和NetworkPolicy的位置第一个children位置
#regin
<#-<Microsoft_Internet_Authentication_Service name="Microsoft_Internet_Authentication_Service">


-<Children>


-<RadiusProfiles name="RadiusProfiles">


-<Children>


-<Test_deny name="拒绝MAC_20250225191551">


-<Properties>

<IP_Filter_Template_Guid dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes">{00000000-0000-0000-0000-000000000000}</IP_Filter_Template_Guid>

<Opaque_Data dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes"/>

<Template_Guid dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes">{00000000-0000-0000-0000-000000000000}</Template_Guid>

<msEAPConfiguration dt:dt="bin.hex" xmlns:dt="urn:schemas-microsoft-com:datatypes"> 1900000000000000000000000000000038000000020000003800000001000000140000002c6309139f605edd59adf035b1fff11ee18df5ac0100000001000000100000001a00000000000000 </msEAPConfiguration>

<msNPAllowDialin dt:dt="boolean" xmlns:dt="urn:schemas-microsoft-com:datatypes">0</msNPAllowDialin>

<msNPAllowedEapType dt:dt="bin.hex" xmlns:dt="urn:schemas-microsoft-com:datatypes"> 19000000000000000000000000000000 </msNPAllowedEapType>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">5</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">3</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">9</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">4</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">10</msNPAuthenticationType2>

<msRADIUSFramedProtocol dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">1</msRADIUSFramedProtocol>

<msRADIUSServiceType dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">2</msRADIUSServiceType>

</Properties>


</Test_deny>


-<Test_deny name="拒绝MAC_20250224192322">  ##自动生成这个是什么策略


-<Properties>

<IP_Filter_Template_Guid dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes">{00000000-0000-0000-0000-000000000000}</IP_Filter_Template_Guid>

<Opaque_Data dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes"> </Opaque_Data>

<Template_Guid dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes">{00000000-0000-0000-0000-000000000000}</Template_Guid>

<msEAPConfiguration dt:dt="bin.hex" xmlns:dt="urn:schemas-microsoft-com:datatypes">1900000000000000000000000000000038000000020000003800000001000000140000002c6309139f605edd59adf035b1fff11ee18df5ac0100000001000000100000001a00000000000000</msEAPConfiguration>

<msNPAllowDialin dt:dt="boolean" xmlns:dt="urn:schemas-microsoft-com:datatypes">0</msNPAllowDialin>

<msNPAllowedEapType dt:dt="bin.hex" xmlns:dt="urn:schemas-microsoft-com:datatypes">19000000000000000000000000000000</msNPAllowedEapType>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">5</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">3</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">9</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">4</msNPAuthenticationType2>

<msNPAuthenticationType2 dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">10</msNPAuthenticationType2>

<msRADIUSFramedProtocol dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">1</msRADIUSFramedProtocol>

<msRADIUSServiceType dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">2</msRADIUSServiceType>

</Properties>

</Test_deny>
</RadiusProfiles>  ###闭合#尝试过测试的位：xml格式严格，


-<NetworkPolicy name="NetworkPolicy"> ##第二个节点，


-<Children>


-<Test_deny name="拒绝MAC_20250225191551">


-<Properties>

<Opaque_Data dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes"/>

<Policy_Enabled dt:dt="boolean" xmlns:dt="urn:schemas-microsoft-com:datatypes">1</Policy_Enabled>  ###这个位置是拒绝的策略enalbe policy 改为1 是启用状态，0为禁用状态

<Policy_SourceTag dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">0</Policy_SourceTag> 

<Template_Guid dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes">{00000000-0000-0000-0000-000000000000}</Template_Guid>

<msNPAction dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes">Test-deny</msNPAction>

<msNPConstraint dt:dt="string" xmlns:dt="urn:schemas-microsoft-com:datatypes">MATCH("Calling-Station-Id=4c5f-705d-f444") </msNPConstraint>

<msNPSequence dt:dt="int" xmlns:dt="urn:schemas-microsoft-com:datatypes">1</msNPSequence>

</Properties>

</Test_deny>
</NetworkPolicy>  ##闭合
#>
#regin