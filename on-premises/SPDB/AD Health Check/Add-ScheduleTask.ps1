<#
使用计划任务每隔10分钟执行一次ADHealthCheck.ps1。
#>
# 配置参数
$TaskName = "ZHAD Health Monitor"   # 计划任务名称
$ScriptPath = "D:\HealthCheck\ADHealthCheck.ps1"  # 替换为您的脚本路径
$User = "NT AUTHORITY\SYSTEM"     # 使用系统账户运行（无需密码，但需权限）
# 或者指定特定用户（需提供密码）：
# $User = "YourDomain\AdminUser"
# $Password = "YourPassword"

# 创建计划任务触发器（每隔10分钟重复一次，持续24小时）
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 1)

# 创建计划任务操作（执行 PowerShell 脚本）
$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

# 配置任务权限（以最高权限运行）
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType ServiceAccount -RunLevel Highest

# 注册计划任务
Register-ScheduledTask -TaskName $TaskName `
  -Trigger $Trigger `
  -Action $Action `
  -Principal $Principal `
  -Description "Monitor AD servers every 10 minutes" `
  -Force

Write-Host "计划任务 '$TaskName' 已创建！" -ForegroundColor Green