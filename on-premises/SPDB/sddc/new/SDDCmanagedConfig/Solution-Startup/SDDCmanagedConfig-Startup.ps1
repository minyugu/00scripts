############################################################
# the script function
# setup prepares for sddc infrastructrue to be ready for remote management.
##### run SDDCmanagedConfig.ps1 ########

$logFilePath = "$($PSScriptRoot)\SDDCmanagedConfig.log"

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

# import Server Name
$servers = (Import-Csv -Path $serverListCSV).resource_name
#### Start Create##########################
foreach ($server in $servers)
{
    If (!([String]::IsNullOrEmpty($server)))
    {
        $server = $server.Trim()
        $invokeOutput = ""
        $Output = ""
        $invokeOutput = Invoke-Command -ComputerName $server -ScriptBlock {
            param(
                $privilegedAccountName,
                $privilegedAccountPassword,
                $unprivilegedAccountName,
                $unprivilegedAccountPassword,
                $domainNetBIOSName,
                $SREAssistAccountName,
                $startToolsPath
            )
            $invokeOutput = ""
            ###create adminsitrator1
            $invokeOutput += "$($env:COMPUTERNAME) Start... ============================================================ $(Get-date)`n"
            $invokeOutput += "Strart Create $privilegedAccountName $(Get-date)`n"
            Try {
                $privilegedAccount = New-LocalUser -PasswordNeverExpires -Name $privilegedAccountName -Password $privilegedAccountPassword -Description "controlled Managed System for Admin Operation" -ErrorAction Stop
            } catch {
                $invokeOutput += "Error::`n"
                $invokeOutput += $_
                $invokeOutput += "`n"
            }
            $invokeOutput += "Completed Create $privilegedAccountName $(Get-date)`n"
            $invokeOutput += "`n"

            # add adminsitrator1 to Local admin group
            $invokeOutput += "Strart Add $privilegedAccountName to Local Admin $(Get-date)`n"
            Try {
                Add-LocalGroupMember -Group "Administrators" -Member $privilegedAccountName -ErrorAction Stop
            } catch {
                $invokeOutput += "Error::`n"
                $invokeOutput += $_
                $invokeOutput += "`n"
            }
            $invokeOutput += "Completed Add $privilegedAccountName to Local Admin $(Get-date)`n"
            $invokeOutput += "`n"

            ###create srereader
            $invokeOutput += "Strart Create $unprivilegedAccountName $(Get-date)`n"
            Try {
                $unPrivilegedAccount = New-LocalUser -PasswordNeverExpires -Name $unprivilegedAccountName -Password $unprivilegedAccountPassword -Description "controlled Managed System for Read Operation" -ErrorAction Stop
            } catch {
                $invokeOutput += "Error::`n"
                $invokeOutput += $_
                $invokeOutput += "`n"
            }
            $invokeOutput += "Completed Create $unprivilegedAccountName $(Get-date)`n"
            $invokeOutput += "`n"

            # add srereader to Local user group
            $invokeOutput += "Strart Add $unprivilegedAccountName to Local group $(Get-date)`n"
            Try {
                Add-LocalGroupMember -Group "Users" -Member $unprivilegedAccountName -ErrorAction Stop
                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $unprivilegedAccountName -ErrorAction Stop
            } catch {
                $invokeOutput += "Error::`n"
                $invokeOutput += $_
                $invokeOutput += "`n"
            }
            $invokeOutput += "Completed Add $unprivilegedAccountName to Local group $(Get-date)`n"
            $invokeOutput += "`n"

            ### Add SREAssist account to Local Admin
            $invokeOutput += "Strart Add $SREAssistAccountName to Local Admin group $(Get-date)`n"
            Try {
                Add-LocalGroupMember -Group "Administrators" -Member $SREAssistAccountName -ErrorAction Stop
            } catch {
                $invokeOutput += "Error::`n"
                $invokeOutput += $_
                $invokeOutput += "`n"
            }
            $invokeOutput += "Completed Add $SREAssistAccountName to Local Admin group $(Get-date)`n"
            $invokeOutput += "`n"

            ####  SREreader Folder ################################################################
            # add SREreader 'reader & execute' permission to StrartTools
            $invokeOutput += "Start Create folder $startToolsPath & add permision ########## $(Get-date)`n"

            if (!(Test-Path -Path $startToolsPath))
            {
                try {
                    $invokeOutput += New-Item -Path "$startToolsPath" -ItemType Directory -ErrorAction Stop
                    $invokeOutput += "`n"
                } catch {
                    $invokeOutput += "Error::`n"
                    $invokeOutput += $_
                    $invokeOutput += "`n"
                }
            }

            $AllowUnprivilegedAccountAcl = New-Object System.Security.AccessControl.FileSystemAccessRule($unprivilegedAccountName,"ReadAndExecute",3,0,"Allow")
            try {
                $DUPAA = (get-Acl $startToolsPath -ErrorAction stop)
                $DUPAA.AddAccessRule($AllowUnprivilegedAccountAcl)
                Set-Acl $startToolsPath -AclObject $DUPAA -ErrorAction Stop
            } catch {
                $invokeOutput += "Error::`n"
                $invokeOutput += $_
                $invokeOutput += "`n"
            }
            $invokeOutput += "Completed Create folder $startToolsPath & add permision ########## $(Get-date)`n"
            $invokeOutput += "`n"


            ###### Create shortcut to startfolder
            $invokeOutput += "Start Create shortcut to startfolder ########## $(Get-date)`n"
            # Make the source file location my path to powershell.exe
            $shortcutTrgetPath = "`"$($env:SystemRoot)\system32\WindowsPowerShell\v1.0\powershell.exe`""
            $shortcutArgs = "C:\StartTools\create-StartToolsShortcute.ps1"

            # Declare where I want to place the shortcut, I placed it on the desktop of whomever is running the script with the dynamic $env:USERNAME which takes the username of whomever is running the script - You can name the shortcut anything you want at the end as long as it ends with .LNK
            $defaultProflePath = (Get-ITemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name Default).Default
            $ShortcutLocation = "$($defaultProflePath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            $ShortcutFilePath = "$($ShortcutLocation)\create-StartToolsShortcute.lnk"
            
            # startup folder not exist default
            if (!(Test-Path -Path $ShortcutLocation))
            {
                try {
                    $invokeOutput += New-Item -Path "$ShortcutLocation" -ItemType Directory -ErrorAction Stop
                    $invokeOutput += "`n"
                } catch {
                    $invokeOutput += "Error::`n"
                    $invokeOutput += $_
                    $invokeOutput += "`n"
                }
            }

            #Create a now com
            $WScriptShell = New-Object -ComObject WScript.Shell

            #create shortcut and provide the location parameter as an argument
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFilePath)

            #set the target path
            $Shortcut.TargetPath = $shortcutTrgetPath
            $Shortcut.Arguments = $shortcutArgs

            #Save the Shortcut
            try {
               $invokeOutput += $Shortcut.Save()
            } catch {
                $invokeOutput += "`nError::`n"
                $invokeOutput += $_
                $invokeOutput += "`n"
            }
            $invokeOutput += "Completed Create shortcut to stratfolder ########## $(Get-date)`n"
            $invokeOutput += "`n"
            return $invokeOutput
        } -ArgumentList $privilegedAccountName, $privilegedAccountPassword, $unprivilegedAccountName, $unprivilegedAccountPassword, $domainNetBIOSName, $SREAssistAccountName, $startToolsPath

        Out-File -FilePath $logFilePath -Encoding utf8 -InputObject $invokeOutput -Append 

        #### Copy StartTools to Server ################################################################
        $Output += "Start copy startTools... $(Get-date)`n"
        $UNCStartToolsPath = $StartToolsPath.Replace(":","$")
        try {
            Copy-Item $startToolsSourceFilePath -Destination "\\$($Server)\$($UNCStartToolsPath)" -Force
            $Output += "`n"
        } catch {
            $invokeOutput += "Error::`n"
            $Output += $_
            $Output += "`n"
        }
        $Output += "Completed copy startTools... $(Get-date)`n"
        $Output += "$server Completed ============================================================ $(Get-date)`n`n"
        Out-File -FilePath $logFilePath -Encoding utf8 -InputObject $Output -Append 
    }
}

# Dest - Copy Start tools