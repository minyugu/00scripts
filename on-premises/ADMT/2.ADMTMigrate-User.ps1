$sourcedomain = "sha.corp.omygu.com"
$sourcedomaincontroller = "sha-dc-01.sha.corp.omygu.com"
$targetdomain = "corp.omygu.org"
$targetdomaincontroller = "org-dc-01.corp.omygu.org"
$passwordserver = $sourcedomaincontroller

$startCsvRow = -1
$endCsvRow = 6

# Usage Examples:

# Migrate GROUP in OU in csv file
<########

Migrate-UserOrGroup -migObjectType "Group" -sourcedomain $sourcedomain -sourcedomaincontroller $sourcedomaincontroller -targetdomain $targetdomain -targetdomaincontroller $targetdomaincontroller -startCsvRow $startCsvRow -endCsvRow $endCsvRow

########>

# Migrate USER in OU in csv file
<########

Migrate-UserOrGroup -migObjectType "User" -sourcedomain $sourcedomain -sourcedomaincontroller $sourcedomaincontroller -targetdomain $targetdomain -targetdomaincontroller $targetdomaincontroller -passwordserver $passwordserver -startCsvRow $startCsvRow -endCsvRow $endCsvRow

########>

# Function to log messages
function Write-Log {
    param (
        $Message,
        [string]$LogPath,
        [switch]$noTimestamp
    )
    if ($noTimestamp)
    {
        $Message | Out-File -Append -FilePath $LogPath
    }
    else
    {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "`n`n=====================`n$Timestamp - $Message" | Out-File -Append -FilePath $LogPath
    }
}

# User Migration
function Migrate-UserOrGroup{
    param (
        [string]$UpdatePath = "$PSScriptRoot\Updated_OU_Structure.csv",
        [string]$LogPath = "$PSScriptRoot\Migration.log",

        [string]$sourcedomain = "sha.corp.omygu.com",
        [string]$sourcedomaincontroller = "sha-dc-01.sha.corp.omygu.com",
        [string]$targetdomain = "corp.omygu.org",
        [string]$targetdomaincontroller = "org-dc-01.corp.omygu.org",
        [string]$conflictoptions = "IGNORE",
        [string]$migratesids = "YES",
        [string]$passwordserver = "sha-dc-01.sha.corp.omygu.com",
        [string]$passwordoption = "COPY",
        [string]$disableoption = "targetsameassource",
        [string]$fixgroupmembership = "YES",

        [int]$startCsvRow,
        [int]$endCsvRow,

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Group")]
        [string]$migObjectType
    )

    # add date to log file
    $charToFind = "\."  # Escape dot since it's a special regex character
    $replacement = "-$migObjectType-$(Get-Date -Format "yyyyMMddHHmmss")."
    $LogPath = $LogPath -replace "(.*)$charToFind", "`$1$replacement"


    Write-Host ""

    if (-Not (Test-Path $UpdatePath)) {
        Write-Host "CSV file not found: $UpdatePath" -ForegroundColor Red
        Write-Log -Message "CSV file not found: $UpdatePath" -LogPath $LogPath
        return
    }

    $OUs = Import-Csv -Path $UpdatePath
    
    If ($startCsvRow -lt 2 -or $endCsvRow -lt 2)
    {
        $startCsvRow = 0
        $endCsvRow = $OUs.count - 1
    }
    else
    {
        $startCsvRow = $startCsvRow - 2
        $endCsvRow = $endCsvRow - 2
    }

    foreach ($OU in $OUs[$startCsvRow..$endCsvRow] )
    {
        # [TOP OU] migrate all users/group in specific OU(/SO:) to target Domain OU (/TO:)

        # check if have user/group in the OU
        try
        {
            $adObject = $Null
            if ( $migObjectType -eq "User" )
            {
                $adObject = Get-ADUser -Filter * -SearchBase $OU.DistinguishedName -SearchScope OneLevel -Server $sourcedomaincontroller -ErrorAction Stop
            }
            elseif ( $migObjectType -eq "Group" )
            {
                $adObject = Get-ADGroup -Filter * -SearchBase $OU.DistinguishedName -SearchScope OneLevel -Server $sourcedomaincontroller -ErrorAction Stop
            }
        
            $adObjectCount = 0
            if ($adObject)
            {
                if ($adObject -isnot [array])
                {
                    $adObjectCount = 1
                }
                else
                {
                    $adObjectCount = $adObject.count
                }
            }
        }
        catch
        {
            Write-Host "[Failed] to get $migObjectType in OU: $($OU.DistinguishedName)" -ForegroundColor Red
            Write-Log -Message "[Failed] to get $migObjectType in OU: $($OU.DistinguishedName)" -LogPath $LogPath
            Write-Log -Message $_ -LogPath $LogPath -noTimestamp

            if ( $migObjectType -eq "User" ) { $OU.UserMigrated = "Failed" } elseif ( $migObjectType -eq "Group" ) { $OU.GroupMigrated = "Failed" }

            continue
        }
        
        If ($adObjectCount -gt 0)
        {
            Write-Host "`nStarting migration ($adObjectCount) $($migObjectType)s in OU: $($OU.DistinguishedName) ..." -ForegroundColor Gray
            
            if ( $migObjectType -eq "User" ) 
            {
                $admtArgs = @( 
                                "/D"
                                "/SD:`"$sourcedomain`""
                                "/SDC:`"$sourcedomaincontroller`""
                                "/SO:`"$($OU.SourceOUPath)`""
                                "/TD:`"$targetdomain`"",
                                "/TDC:`"$targetdomaincontroller`""
                                "/TO:`"$($OU.TargetOUPath)`""
                                "/CO:$conflictoptions"
                                "/MSS:$migratesids"
                                "/PS:`"$passwordserver`""
                                "/PO:$passwordoption"
                                "/DOT:$disableoption"
                                "/FGM:$fixgroupmembership"
                             )
            }
            elseif ( $migObjectType -eq "Group" )
            {
                $admtArgs = @( 
                                "/D"
                                "/SD:`"$sourcedomain`""
                                "/SDC:`"$sourcedomaincontroller`""
                                "/SO:`"$($OU.SourceOUPath)`""
                                "/TD:`"$targetdomain`"",
                                "/TDC:`"$targetdomaincontroller`""
                                "/TO:`"$($OU.TargetOUPath)`""
                                "/CO:$conflictoptions"
                                "/MSS:$migratesids"
                                "/DOT:$disableoption"
                                "/FGM:$fixgroupmembership"
                                "/O `"C:\Users\orgadmin\Desktop\ADMT\optionsExclude.ini`""
                             )
            }

            Try
            {
                $errActPre = $ErrorActionPreference
                $ErrorActionPreference = 'stop'
                
                $result = ""
                $result = C:\Windows\ADMT\ADMT.exe $migObjectType $admtArgs 2>&1

                for ($i = 0; $i -lt $result.count; $i++)
                {
                    if ($result[$i] -like "*WRN:7874 *")
                    {
                        $result[$i-1] = $result[$i-1] -replace "Completed with Warnings or Errors", "Completed with W or E"
                    }
                    elseif ($result[$i] -like "*WRN:7124 *")
                    {
                        $result[$i-1] = $result[$i-1] -replace "Completed with Warnings or Errors", "Completed with Warnings or E"
                    }
                    elseif ($result[$i] -like "*Unable to migrate*")
                    {
                        $result[$i] = $result[$i] -replace "Unable to migrate*", "[errors] Unable to migrate*"
                    }
                    elseif ($result[$i] -like "*Task with task identifier of*")
                    {
                        $result[$i] = $result[$i] -replace "Completed with Warnings or Errors", "Completed with W? or E?"
                    }
                }

                if ( $result -match "Error" )
                {
                    $status = "Errors"
                    $ForegroundColor = "Red"
                }
                elseif ( $result -match "Warning" ) 
                {
                    $status = "Warnings"
                    $ForegroundColor = "Yellow"
                }
                else
                {
                    $status = "Success"
                    $ForegroundColor = "Green"
                }

                Write-Host "[$status] Migrated ($adObjectCount) $($migObjectType)s in OU: $($OU.DistinguishedName)" -ForegroundColor $ForegroundColor
                Write-Log -Message "[$status] migrated ($adObjectCount) $($migObjectType)s in OU: $($OU.DistinguishedName)" -LogPath $LogPath
                Write-Log -Message $result -LogPath $LogPath -noTimestamp

                if ( $migObjectType -eq "User" ) { $OU.UserMigrated = "$status|$adObjectCount" } elseif ( $migObjectType -eq "Group" ) { $OU.GroupMigrated = "$status|$adObjectCount" }
            }
            catch
            {
                Write-Host "[Failed] to migrate ($adObjectCount) $($migObjectType)s in OU: $($OU.DistinguishedName)" -ForegroundColor Red
                Write-Log -Message "Failed to migrated ($adObjectCount) $($migObjectType)s in OU: $($OU.DistinguishedName)" -LogPath $LogPath
                Write-Log -Message $_ -LogPath $LogPath -noTimestamp

                if ( $migObjectType -eq "User" ) { $OU.UserMigrated = "Failed|$adObjectCounts" } elseif ( $migObjectType -eq "Group" ) { $OU.GroupMigrated = "Failed|$adObjectCounts" }
            }
            finally
            {
                $ErrorActionPreference = $errActPre
            }
        }
        else
        {
            Write-Host "[Information] No $migObjectType in OU: $($OU.DistinguishedName)" -ForegroundColor White
            Write-Log -Message "[Information] No $migObjectType in OU: $($OU.DistinguishedName)" -LogPath $LogPath
            
            if ( $migObjectType -eq "User" ) { $OU.UserMigrated = "Skipped" } elseif ( $migObjectType -eq "Group" ) { $OU.GroupMigrated = "Skipped" }
        }
    }

    $OUs | Export-Csv -Path $UpdatePath -NoTypeInformation -Encoding UTF8 -Force
}
