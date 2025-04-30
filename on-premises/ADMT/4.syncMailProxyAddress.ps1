
<#
    Export-Mailaddresses -OUPath "OU=Entra Connect Sync,OU=xSHA,DC=sha,DC=corp,DC=omygu,DC=com" -objectType "User"
    Export-Mailaddresses -OUPath "OU=Entra Connect Sync,OU=xSHA,DC=sha,DC=corp,DC=omygu,DC=com" -objectType "Group"

    Import-Mailaddresses -sourceMailDomain "vanke.com" -targetMailDomain "onewo.com" -objectType "User"
    Import-Mailaddresses -sourceMailDomain "vanke.com" -targetMailDomain "onewo.com" -objectType "Group"
#>

function Export-Mailaddresses
{
    param(
        [string]$OUPath,
        [string]$OutputFile = "$($PSScriptRoot)\Mail$($objectType)s.csv",
        [string]$objectType
    )

    # Check if OU path is provided
    if (-not $OUPath) {
        Write-Host "Please provide the OU distinguished name." -ForegroundColor Red
        return
    }

    # Import Active Directory module
    Import-Module ActiveDirectory

    # Get all users in the specified OU
    if ($objectType -eq "User") {
        $Objects = Get-ADUser -SearchBase $OUPath -Filter * -SearchScope Subtree -Properties mail,proxyAddresses
    } else {
        $Objects = Get-ADGroup -SearchBase $OUPath -Filter * -SearchScope Subtree -Properties mail,proxyAddresses
    }

    # Select relevant properties and export to CSV
    $paExpression = @{
        Name="proxyAddresses"
        expression = {
                        if ($_.proxyAddresses) {
                            $_.proxyAddresses -join ';'
                        }
                     }
    }
    $Objects | Select-Object SamAccountName,Name,UserPrincipalName,mail,$paExpression |
        Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host "Export completed. File saved to $OutputFile" -ForegroundColor Green
}

function Import-Mailaddresses
{
    param(
        [string]$CSVFile = "$($PSScriptRoot)\Mail$($objectType)s.csv",
        [string]$objectType,
        [string]$logFile = "$($PSScriptRoot)\Mail$($objectType)s.log",
        [String]$sourceMailDomain = "@vanke.com",
        [String]$targetMailDomain = "@onewo.com"
    )

    # Check if required parameters are provided
    if (-not (Test-Path $CSVFile)) {
        Write-Host "Please provide both CSV file path and Target OU distinguished name." -ForegroundColor Red
        return
    }

    # Import Active Directory module
    Import-Module ActiveDirectory

    # Import CSV file
    $importObjs = Import-Csv -Path $CSVFile

    foreach ($Obj in $importObjs) {
#        if ($obj.SamAccountName -eq "User4.Migrate" -or $obj.SamAccountName -eq "User5.Migrate")
#        {
#            Write-Host "fund"

        # update user or group in target domain
        if ($objectType -eq "User")
        {
            $existingObj = Get-ADUser -Filter "SamAccountName -eq '$($Obj.SamAccountName)'" -ErrorAction SilentlyContinue
        } else
        {
            $existingObj = Get-ADGroup -Filter "SamAccountName -eq '$($Obj.SamAccountName)'" -ErrorAction SilentlyContinue
        }
    
        if ($existingObj) {
            # mail
            $sourceMail = ''
            $targetMail = ''
            # change domain address to target mail domain
            if ( ($null -ne $Obj.mail) -and (($Obj.mail).trim() -ne '') )
            {
                $sourceMail = ($Obj.mail).trim()
                $targetMail = "$(($sourceMail -split '@', 2)[0])@$($targetMailDomain)"
            }

            # proxyAddresses
            $targetProxyAddresses = @() # new proxy addresses
            if ( -not [string]::IsNullOrEmpty($targetMail) ) #only populating proxy address if mail and proxyaddress exisiting
            {
                #if ($obj.SamAccountName -eq "panzp")
                #{
                #    Write-Host "panzp"
                #}
                if ( ($null -ne $Obj.proxyAddresses) -and (($Obj.proxyAddresses).trim() -ne '') ) 
                { # populating exisiting proxy address 
                    $sourcePrimaryPA = ''
                    $sourceProxyAddresses = $Obj.proxyAddresses -split ";"

                    ForEach ($pa in $sourceProxyAddresses)
                    {
                        if (-not [string]::IsNullOrEmpty($pa))
                        {
                            $pa = $pa.trim()
                            if ( ($pa -ne "") -and ($pa -notlike "*@vanke0.onmicrosoft.com") -and ($pa -notlike "*@vanke0.mail.onmicrosoft.com") )
                            {
                                # find proxyAddresses primary address, then add target mail address to proxyAddresses primary address
                                if ($pa -clike "SMTP:*")
                                {
                                    $sourcePrimaryPA = $pa -replace "SMTP:",""
                                    $targetProxyAddresses += "SMTP:$($targetMail)"
                                    # add source Primary Proxy Address to other proxy address, if it's not in exisiting other proxy address (smtp)
                                    if ( ($sourcePrimaryPA -ne $targetMail) -and "smtp:$($sourcePrimaryPA)" -cnotin $sourceProxyAddresses )
                                    {
                                        $targetProxyAddresses += "smtp:$($sourcePrimaryPA)"
                                    }
                                #add other proxy address to proxyAddresses primary address, if exisiting other proxy address (smtp) not equal target maill address
                                } elseif ( ($pa -clike "smtp:*")) {
                                    $targetProxyAddresses += $pa
                                }
                            }
                        }
                    }
                } else { # populating new proxy address, because source proxy address not exisiting
                    $targetProxyAddresses += "SMTP:$($targetMail)"
                    if($targetMail -ne $sourceMail)
                    {
                        $targetProxyAddresses += "smtp:$($sourceMail)"
                    }
                }
                if ($targetProxyAddresses.count -eq 0)
                {
                    $targetProxyAddresses += "SMTP:$($targetMail)"
                }
            }

            # Update user mail and proxyAddress, and Ensure "User must change password at next login" is disabled
            #Write-Host "mail: $targetMail"
            #Write-Host "targetProxyAddresses: $targetProxyAddresses"
            if ($targetMail -ne '') {
                try {
                        if ($objectType -eq "User")
                        {
                            $existingObj | Set-ADUser -EmailAddress $targetMail -Replace @{proxyAddresses = $targetProxyAddresses} -ChangePasswordAtLogon $false -ErrorAction Stop
                        } else {
                            $existingObj | Set-ADGroup -Replace @{proxyAddresses = $targetProxyAddresses; mail = $targetMail} -ErrorAction Stop
                        }
                    Write-Host "$($objectType) Updated: $($Obj.SamAccountName)" -ForegroundColor Green
                } catch {
                    Write-Host "Cannot update $($objectType): $($Obj.SamAccountName)`n$($_.ToString())" -ForegroundColor red
                }
            } else {
                Write-Host "$objectType object no mail attribute: $($Obj.SamAccountName)" -ForegroundColor Yellow
            }
        } else {
            # Create new user
            Write-Host "no $objectType object find: $($Obj.SamAccountName)" -ForegroundColor Yellow
        }
#}
    }
    Write-Host "Import completed successfully." -ForegroundColor Cyan
}