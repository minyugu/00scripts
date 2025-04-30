#region Entra Sync Connect
cd "%ProgramFiles%\Microsoft Azure AD Sync\bin"
csexport "vanke0.onmicrosoft.com - AAD" "C:\Users\orgadmin\Desktop\entraCommand\export.xml" /f:x

Import-Module 'C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync\ADSync.psd1'
Import-Module ADSync

Start-ADSyncSyncCycle -PolicyType Delta

Start-ADSyncSyncCycle -PolicyType Initial

Get-ADSyncScheduler 
#endregion


#region Graph Entra ID
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force

Update-Module -Name Microsoft.Graph

$env:PSModulePath += ";C:\Users\s-zane\Documents\WindowsPowerShell\Modules\"
Import-Module -Name Microsoft.Graph -Force
Import-Module -Name Microsoft.Graph.Authentication -Force

Connect-MgGraph -Scopes "User.ReadWrite.All"

$user = "user2.Migrate.newM@corp.omygu.com"
$user = "syncuser3@corp.omygu.com"
Get-MgUser -UserId $user | ft UserPrincipalName,ProxyAddresses,Mail,MailNickname,OtherMails
Get-MgUser -UserId $user | fl *
Set-MgUser -UserId $user -ProxyAddresses @("smtp:user2.Migrate.newS@corp.omygu.com", "SMTP:user2.Migrate@corp.omygu.com")
Get-MgUser -UserId $user | Select-Object -ExpandProperty ProxyAddresses


Connect-MgGraph -Scopes "Group.ReadWrite.All"

$allDeletedGroup = Get-MgGroup -All | Where-Object {$_.OnPremisesDomainName -eq 'vanke.net.cn'}
$allDeletedGroup | Sort-Object DisplayName| ft DisplayName,Mail,CreatedDateTime,OnPremisesLastSyncDateTime,OnPremisesDomainName,Members,MemberOf,ProxyAddresses

#$keepGroups1 = (Get-MgGroup -Search "DisplayName:AIPUsers" -ConsistencyLevel eventual)
$keepGroups2 = (Get-MgGroup -Search "DisplayName:万翼科技-AIP超级用户组" -ConsistencyLevel eventual)

$allDeletedGroup = $allDeletedGroup | where {$_.id -ne $keepGroups2.id}
$allDeletedGroup.Count

$allDeletedGroup | foreach {Remove-MgGroup -GroupId $_.id}