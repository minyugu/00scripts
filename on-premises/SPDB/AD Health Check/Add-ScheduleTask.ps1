<#
ʹ�üƻ�����ÿ��10����ִ��һ��ADHealthCheck.ps1��
#>
# ���ò���
$TaskName = "ZHAD Health Monitor"   # �ƻ���������
$ScriptPath = "D:\HealthCheck\ADHealthCheck.ps1"  # �滻Ϊ���Ľű�·��
$User = "NT AUTHORITY\SYSTEM"     # ʹ��ϵͳ�˻����У��������룬����Ȩ�ޣ�
# ����ָ���ض��û������ṩ���룩��
# $User = "YourDomain\AdminUser"
# $Password = "YourPassword"

# �����ƻ����񴥷�����ÿ��10�����ظ�һ�Σ�����24Сʱ��
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 1)

# �����ƻ����������ִ�� PowerShell �ű���
$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

# ��������Ȩ�ޣ������Ȩ�����У�
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType ServiceAccount -RunLevel Highest

# ע��ƻ�����
Register-ScheduledTask -TaskName $TaskName `
  -Trigger $Trigger `
  -Action $Action `
  -Principal $Principal `
  -Description "Monitor AD servers every 10 minutes" `
  -Force

Write-Host "�ƻ����� '$TaskName' �Ѵ�����" -ForegroundColor Green