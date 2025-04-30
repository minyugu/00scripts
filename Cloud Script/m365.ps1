# Exchange online
Install-Module -Name ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName my@omygu.com
get-mailbox
Enable-Mailbox


# Autopilot Capture the Hardware ID
mkdir c:\HWID
Set-Location c:\HWID
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
Install-Script -Name Get-WindowsAutopilotInfo -Force
$env:Path += ";C:\Program Files\WindowsPowerShell\Scripts"
Get-WindowsAutopilotInfo.ps1 -OutputFile AutopilotHWID.csv

# get status for Azure Multi-Factor Auth Connector
Install-Module MSOnline
Install-Module AzureADPreview
Connect-MsolService -AzureEnvironment AzureChinaCloud
Get-MsolServicePrincipal -AppPrincipalId 1f5530b3-261a-47a9-b357-ded261e17918

# Set up a trust between your SAML identity provider and Azure AD
Connect-MgGraph  -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Directory.ReadWrite.All" -Environment China
Get-

set-MsolDomainAuthentication

# Get domain federation settings
Get-MsolDomainFederationSettings -DomainName seu.edu.cn
Get-MgDomainFederationConfiguration -DomainId omygu.com