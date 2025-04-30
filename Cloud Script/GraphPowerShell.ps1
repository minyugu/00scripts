Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber

Update-Module -Name Microsoft.Graph

Import-Module -Name Microsoft.Graph
Import-Module Microsoft.Graph.Authentication -Force

Connect-MgGraph -Scopes "User.ReadWrite.All"

$user = "user2.Migrate.newM@corp.omygu.com"
$user = "syncuser3@corp.omygu.com"
Get-MgUser -UserId $user | ft UserPrincipalName,ProxyAddresses,Mail,MailNickname,OtherMails

Get-MgUser -UserId $user | fl *

Set-MgUser -UserId $user -ProxyAddresses @("smtp:user2.Migrate.newS@corp.omygu.com", "SMTP:user2.Migrate@corp.omygu.com")


Get-MgUser -UserId $user | Select-Object -ExpandProperty ProxyAddresses



Connect-MgGraph -Scopes "Group.ReadWrite.All"

$group = "groupall@corp.omygu.com"

Get-MgGroup | fl *
Get-MgGroup | Where-Object {$_.DisplayName -eq "A155集团物业全体员工"}  | FL

Get-MgGroup | Sort-Object DisplayName| ft DisplayName,Mail,CreatedDateTime,OnPremisesLastSyncDateTime,OnPremisesDomainName,Members,MemberOf,ProxyAddresses

Get-MgGroup | Where-Object {$_.DisplayName -eq "万科集团"} | ft DisplayName,Mail,CreatedDateTime,OnPremisesLastSyncDateTime,OnPremisesDomainName,Members#,ProxyAddresses

$groupId = Get-MgGroup | Where-Object {$_.Mail -eq "Goup1.Migrate@corp.omygu.com"} | select Id
$groupId.Id.GetType()
Remove-MgGroup  -GroupId $groupId.Id



#remove source domain group
$oldGroups.Id | foreach {Remove-MgGroup -GroupId $_}

$oldGroups = Get-MgGroup | Where-Object {$_.OnPremisesDomainName -eq 'sha.corp.omygu.com'}

$oldGroups = Get-MgGroup | Where-Object {$_.OnPremisesDomainName -eq 'corp.omygu.org'}

