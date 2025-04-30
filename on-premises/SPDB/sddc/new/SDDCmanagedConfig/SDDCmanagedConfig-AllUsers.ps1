############################################################
# the script function
# setup prepares for sddc infrastructrue to be ready for remote management.
##### run SDDCmanagedConfig.ps1 ########

$logFilePath = "$($PSScriptRoot)\SDDCmanagedConfig.log"
$shortcutePs1Path = "$($PSScriptRoot)\StartTools\create-StartToolsShortcute.ps1"

# Administrator1 account
$privilegedAccountName = "Administrator1"
$privilegedAccountPassword = 'dkw#23s!dfLdw'
$privilegedAccountPassword = ConvertTo-SecureString -AsPlainText $privilegedAccountPassword -Force

# srereader account
$unprivilegedAccountName = "SREreader"
$unprivilegedAccountPassword = 'lfeJ>iuJHJ)<'
$unprivilegedAccountPassword = ConvertTo-SecureString -AsPlainText $unprivilegedAccountPassword -Force

#$domainNetBIOSName = (gwmi WIN32_NTDomain).DomainName
#$domainNetBIOSName = (get-WmiObject -Namespace root\cimv2 -Class Win32_computerSystem).Domain
#$domainNetBIOSName = $domainNetBIOSName.Split('.')[0]
$domainNetBIOSName = ($env:USERDOMAIN)

# SREAssist account name
$SREAssistAccountName = "$($domainNetBIOSName)\SREAssist"


#################### startTools path ###################################
# Local startTools path
$startToolsPath = "C:\StartTools"

# Source - Copy Start tools
$startToolsSourceFilePath = "$($PSScriptRoot)\StartTools\*.*"

# ServerList Path
$serverListCSV = "$($PSScriptRoot)\ServerList.csv"

# start Log
Out-File -FilePath $logFilePath -Encoding utf8 -InputObject "$(Get-Date)`n"

# import Server Name
$servers = (Import-Csv -Path $serverListCSV).resource_name
#### Start Create##########################
foreach ($server in $servers)
{
    If (!([String]::IsNullOrEmpty($server)))
    {
        $server = $server.Trim()
        $output = "[$($server)]"
        $output += Invoke-Command -ComputerName $server -ScriptBlock {
            param(
                $privilegedAccountName,
                $privilegedAccountPassword,
                $unprivilegedAccountName,
                $unprivilegedAccountPassword,
                $domainNetBIOSName,
                $SREAssistAccountName,
                $startToolsPath
            )
            $output = ""
            ###create adminsitrator1
            $output += "$($env:COMPUTERNAME) Start... ============================================================ $(Get-date)`n"
            $output += "Strart Create $privilegedAccountName $(Get-date)`n"
            Try {
                $privilegedAccount = New-LocalUser -PasswordNeverExpires -Name $privilegedAccountName -Password $privilegedAccountPassword -Description "controlled Managed System for Admin Operation" -ErrorAction Stop
            } catch {
                $output += "Error::$($_)`n"
            }
            $output += "Completed Create $privilegedAccountName $(Get-date)`n`n"

            # add adminsitrator1 to Local admin group
            $output += "Strart Add $privilegedAccountName to Local Admin $(Get-date)`n"
            Try {
                Add-LocalGroupMember -Group "Administrators" -Member $privilegedAccountName -ErrorAction Stop
            } catch {
                $output += "Error::$($_)`n"
            }
            $output += "Completed Add $privilegedAccountName to Local Admin $(Get-date)`n`n"

            ###create srereader
            $output += "Strart Create $unprivilegedAccountName $(Get-date)`n"
            Try {
                $unPrivilegedAccount = New-LocalUser -PasswordNeverExpires -Name $unprivilegedAccountName -Password $unprivilegedAccountPassword -Description "controlled Managed System for Read Operation" -ErrorAction Stop
            } catch {
                $output += "Error::$($_)`n"
            }
            $output += "Completed Create $unprivilegedAccountName $(Get-date)`n`n"

            # add srereader to Local user group
            $output += "Strart Add $unprivilegedAccountName to Local group $(Get-date)`n"
            Try {
                Add-LocalGroupMember -Group "Users" -Member $unprivilegedAccountName -ErrorAction Stop
                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $unprivilegedAccountName -ErrorAction Stop
            } catch {
                $output += "Error::$($_)`n"
            }
            $output += "Completed Add $unprivilegedAccountName to Local group $(Get-date)`n`n"

            ### Add SREAssist account to Local Admin
            $output += "Strart Add $SREAssistAccountName to Local Admin group $(Get-date)`n"
            Try {
                Add-LocalGroupMember -Group "Administrators" -Member $SREAssistAccountName -ErrorAction Stop
            } catch {
                $output += "Error::$($_)`n"
            }
            $output += "Completed Add $SREAssistAccountName to Local Admin group $(Get-date)`n`n"

            ####  StartTools Folder ################################################################
            $output += "Start Create folder $startToolsPath & add permision ########## $(Get-date)`n"

            # add create StrartTools folder
            if (!(Test-Path -Path $startToolsPath))
            {
                try {
                    $output += New-Item -Path "$startToolsPath" -ItemType Directory -ErrorAction Stop
                    $output += "`n"
                } catch {
                    $output += "Error::$($_)`n"
                }
            }

            # add SREreader 'reader & execute' permission to StrartTools folder
            try {
                $AllowUnprivilegedAccountAcl = New-Object System.Security.AccessControl.FileSystemAccessRule($unprivilegedAccountName,"ReadAndExecute",3,0,"Allow")
                $DUPAA = (get-Acl $startToolsPath -ErrorAction stop)
                $DUPAA.AddAccessRule($AllowUnprivilegedAccountAcl)
                Set-Acl $startToolsPath -AclObject $DUPAA -ErrorAction Stop
            } catch {
                $output += "Error::$($_)`n"
            }
            $output += "Completed Create folder $startToolsPath & add permision ########## $(Get-date)`n`n"
            return $output
        } -ArgumentList $privilegedAccountName, $privilegedAccountPassword, $unprivilegedAccountName, $unprivilegedAccountPassword, $domainNetBIOSName, $SREAssistAccountName, $startToolsPath

        ###### Create StartTools shortcut to Public Desktop

        $output += Invoke-Command -ComputerName $server -FilePath $shortcutePs1Path -ArgumentList $unprivilegedAccountName

        #### Copy StartTools to Server ################################################################
        $output += "Start copy startTools... $(Get-date)`n"
        $UNCStartToolsPath = $StartToolsPath.Replace(":","$")
        try {
            Copy-Item $startToolsSourceFilePath -Destination "\\$($Server)\$($UNCStartToolsPath)" -Force
            $output += "`n"
        } catch {
            $output += "Error::$($_)`n"
        }
        $output += "Completed copy startTools... $(Get-date)`n"
        $output += "$server Completed ============================================================ $(Get-date)`n`n"
        Out-File -FilePath $logFilePath -Encoding utf8 -InputObject $output -Append
    }
}

# Dest - Copy Start tools