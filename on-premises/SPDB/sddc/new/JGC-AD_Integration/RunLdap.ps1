Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
Import-Module .\LdapLogAnalyzer.ps1 -Force


$log = "D:\Users\c-gumy\My Document\script-new\JGC-AD_Integration\ldapLogs\2889.evtx"
$log = "d:\Users\c-gumy\My Document\script-new\JGC-AD_Integration\ldapLogs\2889_1138.evtx"
Analyse-LdapLog -evtxFile $log -RemoveDuplicateProperty ID,IP,User | Export-Csv "$($log).csv" -NoTypeInformation -Encoding UTF8


# check Id 3039,3074,3075
(Get-ChildItem -Path ".\ldapLogs\" -File).FullName | ForEach-Object -Process {
        $_
        (Get-WinEvent -FilterHashtable @{Path=$_;Id=3039,3074,3075}).count
    }

(Get-ChildItem -Path ".\ldapLogs\" -File).FullName | ForEach-Object -Process {
    Start-Job -ScriptBlock {
        Param($log,$scriptPath)
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
        Import-Module "$($scriptPath)\LdapLogAnalyzer.ps1" -Force
        Analyse-LdapLog -evtxFile $log -RemoveDuplicateProperty ID,IP,User | Export-Csv "$($log).csv" -NoTypeInformation -Encoding UTF8
    } -ArgumentList $_,((Get-Item .).FullName)
}

((Get-Job).ChildJobs) | select Id,Error,State,PSBeginTime,PSEndTime | ft

#region get sid
$strSID = "S-1-5-21-263442704-3334799138-249559749-245517"
$uSid = [ADSI]"LDAP://<SID=$strSID>"
$uSid.sAMAccountName
$uSid.distinguishedName
#endregion get sid

    "$($env:USERDOMAIN)\$($uSid.)"

"$($env:USERDOMAIN)\$( ([ADSI]"LDAP://<SID=$strSID>").sAMAccountName )"

#region get sid==================================================
$csvFile = ''
 Import-Csv -Path $csvFile | ForEach-Object -Process {
        if ( [String]::IsNullOrEmpty($_.User) -eq $False)
        {
            $userName = ''
            $userName = $_.User.Trim()
            if ( [String]::IsNullOrEmpty($userName) -eq $False )
            {
                if ( $userName -eq 'S-1-5-7' )
                {
                    $_.User = 'Anonymous Logon'
                }
                elseif ( $userName -eq 'S-1-5-18' )
                {
                    $_.User = 'System'
                }
                elseif ( $userName -like ("S-1-5-*") )
                {
                    $uSid = $null
                    try
                    {
                        $uSid = [ADSI]"LDAP://<SID=$userName>"
                    } catch {}

                    if ( [String]::IsNullOrEmpty($uSid.sAMAccountName) -eq $False )
                    {
                        $_.User = "$($env:USERDOMAIN)\$($uSid.sAMAccountName)"
                    }
                }
            }
         }
         $_ | Export-Csv -Path "$($csvFile)_updated.csv" -NoTypeInformation -Encoding UTF8 -Append
    }
#endregion