@PowerShell.exe -NoExit -File "%~dp0get_folder_acl_DomainUser.ps1" "Domain Users" "35"

REM @PowerShell.exe -NoExit -File "%~dp0get_folder_acl_DomainUser.ps1" "Domain Users" "35" "Excluded" "C:\0000mgtest\mytestfolder"
REM PowerShell.exe -NoExit -File "%~dp0get_folder_acl_DomainUser.ps1" "Domain Users" "35" "OnlyIncluded" "C:\0000mgtest\mytestfolder"