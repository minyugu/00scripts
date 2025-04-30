#################################
#
# ver 0.43 20240809 power by mygu
#
# https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights?redirectedfrom=MSDN
# GENERIC_ALL (268435456)
# GENERIC_EXECUTE (536870912)
# GENERIC_WRITE (1073741824)
# GENERIC_READ(2147483648)
#
# Sample command
# @PowerShell.exe -NoExit -File "%~dp0get_folder_acl_DomainUser.ps1" "Domain Users" "35"
#
# @PowerShell.exe -NoExit -File "%~dp0get_folder_acl_DomainUser.ps1" "Domain Users" "35" "Excluded" "K:\DN2FP13\l-m_public"
#
# @PowerShell.exe -NoExit -File "%~dp0get_folder_acl_DomainUser.ps1" "Domain Users" "35" "OnlyIncluded" "K:\DN2FP13\l-m_public"
#
#################################

param
(
    [Parameter(Mandatory=$false)]
    [String]$idName = "Domain Users",

    [Parameter(Mandatory=$false)]
    [Int]$folderDepth = 25,

    [Parameter(Mandatory=$false)]
    [String]$folderExcIncOp,
    
    [Parameter(Mandatory=$false)]
    [String]$folderNameExcInc
)

#check admin permission for runas
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin)
{
    Write-Warning "You need to execute this script by Run as Administrator. try again?"
    Exit 1
}

#$Computers = @("odaws.sha.corp.omygu.com","sha-hv-01.sha.corp.omygu.com","sha-hv-01x.sha.corp.omygu.com")

$Computers = (Import-Csv -Path "$($PSScriptRoot)\servers.csv" -Header "name").name

$IdentityName = "*\$($idName)"
$logFileFolder = "0_shareFolderACLscan"
$reportFileName = "$($PSScriptRoot)\scriptExReport.csv"

$computerCount = 0
foreach ($Computer in $Computers)
{
    $computerCount++
    $info = ""
    $info = "[s_$computerCount/$($Computers.count)]=====Started Scaning for [$Computer]======================================================================================"
    Write-Host $info -ForegroundColor Green

    $oResult = $null
    try
    {
        # remote to server scan ACL
        $oResult = Invoke-Command -ComputerName $Computer -ScriptBlock {
            param(
                [String]$IdentityName,
                [String]$logFileFolder,
                [String]$folderExcIncOp,
                [String]$folderNameExcInc,
                [Int]$folderDepth
            )

            $isDeepFolderTest = $false

            $haveInvalidNameFolder = 0
            $totalShareFolder = 0
            $totalShareFolderPermission = 0
            $totalSubFolder = 0
            $totalACL = 0
            $totalGetSmbError = 0
            $totalGetFolderError = 0
            $totalGetAclError = 0
            $output = ""
            $info = ""
            $info = "[$($env:COMPUTERNAME)]$(Get-Date)"
            Write-Host $info
            $output += $info

            # prepare log folder and log file name

            $logFileFolder = "$($env:SystemDrive)\$logFileFolder"
            $logFileFullPath = "$logFileFolder\$([System.Net.Dns]::GetHostByName($env:computerName).HostName)_sfACL.log"
            if (!(Test-Path -Path $logFileFolder))
            {
                try
                {
                    New-Item -ItemType Directory -Path $logFileFolder -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    $info = "Create log folder failed++++++++++++++++++++++++++++++++ `n" + ($_ | Out-String -Width 2000)
### return 1
                    return 1, $info, $($env:SystemDrive), $logFileFullPath, "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA"
                }
            }

##### 1. get share folder
            $Error.Clear()
            $shareFolders = $null

# get share folder with param including & excluding
            if ($folderExcIncOp -eq "OnlyIncluded")
            {
                $shareFolders = (Get-SmbShare -Special $false -ErrorAction SilentlyContinue) | Where-Object {$_.Path -eq $folderNameExcInc}
            } elseif ($folderExcIncOp -eq "Excluded") {
                $shareFolders = (Get-SmbShare -Special $false -ErrorAction SilentlyContinue) | Where-Object {$_.Path -ne $folderNameExcInc}
            } else {
                $shareFolders = (Get-SmbShare -Special $false -ErrorAction SilentlyContinue)
            }

            # get Share Folder number
            if ($shareFolders)
            {
                if ($shareFolders -is [array])
                {
                    $totalShareFolder = $shareFolders.count
                } else {
                    $totalShareFolder = 1
                }
            }

            $info = "`n`n$($totalShareFolder) share folder be found"
            Write-Host $info
            $output += $info

            # record error if Get-SmbShare encountered error
            if ($Error.Count -gt 0)
            {
                $output += "`n`n***********get share folder error [$($Error.Count)]**************`n"
                $output += ($Error.Exception | Out-String -Width 2000)
                $totalGetSmbError = $Error.Count
            }

            if (!$shareFolders) 
            {
                $info = "No share folder be found"
                $output += "`n`n======================$($info)======================"
                Out-File -InputObject $output -FilePath $logFileFullPath -Encoding utf8
                Start-Sleep -Seconds 2
### Return 2
                return 2, $info, $($env:SystemDrive), $logFileFullPath, "NA", $totalGetSmbError, "NA", "NA", $totalShareFolder, "NA", "NA", "NA"
            } else {
                $output += "`n"
                $output += ($shareFolders | Out-String -Width 2000)
                $Error.Clear()
##### 2. get share permission
                $shareFolderPerm = $null
                $shareFolderPerm = ($shareFolders | Get-SmbShareAccess -ErrorAction SilentlyContinue)
                $totalShareFolderPermission = ($shareFolderPerm | Where {$_.AccountName -like $IdentityName}).AccountName.Count
                $output += ($shareFolderPerm | Out-String -Width 2000)
        
                # record error if Get-SmbShareAccess encountered error
                if ($Error.Count -gt 0)
                {
                    $output += "`n`n***********get share folder access error [$($Error.Count)]**************`n"
                    $output += ($Error.Exception | Out-String -Width 2000)
                }

                $i = 0
                Foreach ($folderName in $shareFolders.Path)
                {
                    $startedTime = Get-Date
                    $i++
                    $info = "`n[f_$i/$($shareFolders.Path.count)]Start recurse all sub folder=================================='$folderName'=================================="
                    Write-Host $info -ForegroundColor "Yellow"
                    $output += $info

##### 3. recurse all sub folder under share folder root
                    $Error.Clear()
                    $folders = $null
                    $folders = Get-ChildItem -recurse -force $folderName -Directory -ErrorAction SilentlyContinue -Depth $folderDepth | Select-Object FullName,Name

                    # add parent folder 
                    $parentFolder = $null
                    $parentFolder = Get-Item -Path $folderName | Select-Object FullName,Name
                    if (!$folders)
                    {
                        $folders = @($parentFolder)
                    } else {
                        if ($folders -is [Array])
                        {
                            $folders += $parentFolder
                        } else {
                            $folders = @($folders, $parentFolder)
                        }
                    }
                    $totalSubFolder += $folders.Count

                    $subFolderGetCompletedData = Get-Date
                    $info = "Got $($folders.Count - 1) subdirectory [take $([math]::floor(($subFolderGetCompletedData - $startedTime).TotalSeconds)) seconds]"
                    Write-Host $info
                    $output += "`n$info"

                    # record error if Get-ChildItem encountered error
                    if ($Error.Count -gt 0)
                    {
                        $output += "`n`n***********recurse folder error [$($Error.Count)]**************`n"
                        $output += ($Error.Exception | Out-String -Width 2000)
                        $totalGetFolderError = $totalGetFolderError + $Error.Count
                    }

                    # check the folders ACL with specific identity name
                    $ii = 0
                    $Error.Clear()
                    foreach ($fol in $folders)
                    {
##### 4. get ACL with specified identity reference
                        $domainUserACL = $null
                        $domainUserACL = get-acl -Path $fol.FullName -ErrorAction SilentlyContinue | select -ExpandProperty access | where {$_.IdentityReference -like $IdentityName -and $_.IsInherited -eq $False}

                        if ($domainUserACL)
                        {
                            $ii++
                            $output += "`n`n-----------$($fol.FullName)---------------------------------"
                            $output += ($domainUserACL | Out-String -Width 2000)
                        }

                    }

                    # record error if get-acl encountered error
                    if ($Error.Count -gt 0)
                    {
                        $output += "`n`n***********get acl error [$($Error.Count)]**************`n"
                        $output += ($Error.Exception | Out-String -Width 2000)
                        $totalGetAclError = $totalGetAclError + $Error.Count
                    }

##### 5. get folders that name is empty
                    $invalidNameFolders = $null
                    $invalidNameFolders = $folders | where {($_.Name.Trim()) -eq ''}
                    if ($invalidNameFolders.Count -gt 0)
                    {
                        $output += "`n`n********************found Folder with invalid Name [$($invalidNameFolders.Count)]********************`n"
                        $output += ($invalidNameFolders.Fullname | Select-Object -Unique | Out-String -Width 2000)
                        $haveInvalidNameFolder += ($invalidNameFolders.Fullname | Select-Object -Unique).count
                    }

                    # output folder completed info
                    $info =  "[f_$i/$($shareFolders.Path.count)]Completed checking the folders ACL===========found [$ii]/[$($folders.Count)] ACL in '$folderName'================[take $([math]::floor(((Get-Date) - $subFolderGetCompletedData).TotalSeconds)) seconds]"
                    $totalACL = $totalACL + $ii
                    Write-Host $info
                    $output += "`n$($info)`n"

# GC 1
                    Remove-Variable folders
                    Remove-Variable domainUserACL
                    Remove-Variable invalidNameFolders
                    [system.gc]::Collect()
                }

                # output computer completed info
                if ($haveInvalidNameFolder -gt 0)
                {
                    $info =  "`n**Found [$($haveInvalidNameFolder)] folder/s with INVALID name**"
                    Write-Host $info -ForegroundColor DarkYellow
                    $output += "$($info)`n"
                }
                $info =  "`nCompnter Scan Done. Found [$($totalACL)]/[$totalSubFolder] ACL. $(Get-Date)"
                Write-Host $info
                $output += "$($info)`n"

                Out-File -InputObject $output -FilePath $logFileFullPath -Encoding utf8

                Start-Sleep -Seconds 2
    ### return 0
                return 0, "Succeeded checking the folders ACL", $($env:SystemDrive), $logFileFullPath, $totalACL, $totalGetSmbError, $totalGetFolderError, $totalGetAclError, $totalShareFolder, $totalShareFolderPermission, $totalSubFolder, $haveInvalidNameFolder
            }
        } -ArgumentList $IdentityName,$logFileFolder,$folderExcIncOp,$folderNameExcInc,$folderDepth -ErrorAction Stop
    } Catch {
        $info = $_.Exception.Message
        Write-Host $info -ForegroundColor Red
### return -1
        $oResult = @(-1,"`"$info`"","NA","NA","NA","NA","NA","NA","NA","NA","NA","NA")
    }

    $outputScriptlog = ""
    # for log output add header
    if ($computerCount -eq 1)
    {
        $outputScriptlog += "ServerName,ResultCode,ResultInfo,LogFilePath,CopyLogFile,ShareFolder,$($idName)_SFPermission,FolderCount,$($idName)_ACL,Error_SmbError,Error_Folder,Error_Acl,InvalidFolder`n"
    }

    # pull server log to PS script execution Server
    if($oResult -and $oResult -is [Array])
    {
        if (($oResult[0] -eq 0) -or ($oResult[0] -eq 2))
        {
            try
            {
                $sourcePath = "\\$Computer\$($oResult[2].Replace(":","$"))\$logFileFolder\*.*"
                Copy-Item -Path $sourcePath -Destination "$($PSScriptRoot)\server_logs" -ErrorAction Stop
                $outputScriptlog += "$($Computer),$($oResult[0]),$($oResult[1]),$($oResult[3]),success,$($oResult[8]),$($oResult[9]),$($oResult[10]),$($oResult[4]),$($oResult[5]),$($oResult[6]),$($oResult[7]),$($oResult[11])"
            } catch {
                $outputScriptlog += "$($Computer),$($oResult[0]),$($oResult[1]),$($oResult[3]),failed,$($oResult[8]),$($oResult[9]),$($oResult[10]),$($oResult[4]),$($oResult[5]),$($oResult[6]),$($oResult[7]),$($oResult[11])"
            }
        } else {
            $outputScriptlog += "$($Computer),$($oResult[0]),$($oResult[1]),$($oResult[3]),NA,$($oResult[8]),$($oResult[9]),$($oResult[10]),$($oResult[4]),$($oResult[5]),$($oResult[6]),$($oResult[7]),$($oResult[11])"
        }
    } else {
        $outputScriptlog += "$($Computer),-404,No return from Remote PS,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA"
    }

    # screen completed message
    $info = "[s_$computerCount/$($Computers.count)]=====completed Scaning for [$Computer]====================================================================================`n`n"
    Write-Host $info -ForegroundColor DarkGray
    
    if ($computerCount -eq 1)
    {
        Out-File -InputObject $outputScriptlog -FilePath $reportFileName -Encoding utf8
    } else {
        Out-File -InputObject $outputScriptlog -FilePath $reportFileName -Encoding utf8 -Append
    }
}
Write-Host "Good Job`n"