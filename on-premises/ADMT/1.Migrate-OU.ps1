# Usage Examples:

# the ou want to be migrated
#$SourceRootOU = "OU=物业事业部,OU=计算机,DC=vanke,DC=net,DC=cn"
$SourceRootOU = "OU=物业事业部,OU=万科集团,DC=vanke,DC=net,DC=cn"


# the parent OU of Source Root OU in targe Domain
$TargetRootOU = "DC=onewo,DC=net,DC=cn"

<#
# Export a specific OU subtree: (run at Source domain DC)

Export-OUStructure -RootOU $SourceRootOU
#>

<#
# Import under a different root: (run at Target domain DC)

Import-OUStructure -TargetRootOU $TargetRootOU -SourceRootOU $SourceRootOU
#>

# Function to get the script directory
function Get-ScriptDirectory {
    # $scriptPath = $MyInvocation.MyCommand.Path
    $scriptPath = $PSScriptRoot
    if ($scriptPath) {
        #return Split-Path -Parent $scriptPath
        return $scriptPath
        Write-Host $scriptPath
    } else {
        return "C:\"
    }
}

# Function to log messages
function Write-Log {
    param (
        [string]$Message,
        [string]$LogPath
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -Append -FilePath $LogPath
}

# Export OUs from the Source Domain
function Export-OUStructure {
    param (
        [string]$RootOU = "",
        [string]$ExportPath = "",
        [string]$LogPath = ""
    )

    $ScriptDir = Get-ScriptDirectory
    if (-not $ExportPath) { $ExportPath = "$ScriptDir\OU_Structure.csv" }
    if (-not $LogPath) { $LogPath = "$ScriptDir\OU_Migration.log" }

    Try {
        #$Filter = if ($RootOU -ne "") { "DistinguishedName -like '*$RootOU*'" } else { "*" }
        #$OUs = Get-ADOrganizationalUnit -Filter $Filter -Properties DistinguishedName, Name, ProtectedFromAccidentalDeletion

        if ([String]::IsNullOrEmpty($RootOU))
        {
            $OUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName, Name, ProtectedFromAccidentalDeletion -SearchScope Subtree
        }
        else
        {
            $OUs = Get-ADOrganizationalUnit -SearchBase $RootOU -Filter * -Properties DistinguishedName, Name, ProtectedFromAccidentalDeletion -SearchScope Subtree
        }

#region Expression of popule Source OU Pobject Path
        # this csv colume will be used by ADMT.exe parameter /SO: (Value sample: xSHA/Entra Connect Sync/ADMT/migrate1)
        $SourceOUPathProps = @{
            Name = "SourceOUPath"
            Expression = {
                # get Source OU Object Path, the Path NOT included Domain Name Path
                $sOuPathArray = $null
                $sOuPathArray = $_.DistinguishedName  -split "," | Where-Object {$_ -notlike "DC=*"}
                $sOuPathArray = $sOuPathArray | ForEach-Object {$_ -replace "OU=", ""}
                $sOuPathArray[-1..-($sOuPathArray.Count)] -join "/"
            }
        }
#endregion
        
        $OUs | Select-Object DistinguishedName, Name, @{ Name="ParentOU";Expression={(($_.DistinguishedName -split ",",2)[1])} }, ProtectedFromAccidentalDeletion, $SourceOUPathProps, `
                                                      @{ Name="TargetOUPath";Expression={""} }, @{ Name="OuMigrated";Expression={""} }, @{ Name="UserMigrated";Expression={""} }, `
                                                      @{ Name="GroupMigrated";Expression={""} } `
             | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8 -Force

        Write-Host "OU structure exported to: $ExportPath"
        Write-Log -Message "Exported OU structure to: $ExportPath" -LogPath $LogPath
    } Catch {
        Write-Host "[Failed] to export OUs: $_" -ForegroundColor Red
        Write-Log -Message "[Failed] to export OUs: $_" -LogPath $LogPath
    }
}

# Import OUs to the Target Domain
function Import-OUStructure {
    param (
        [string]$ImportPath = "",
        [string]$UpdatePath = "",
        [string]$TargetRootOU = "",
        [string]$SourceRootOU = "",
        [string]$LogPath = ""
    )

    $ScriptDir = Get-ScriptDirectory
    if (-not $ImportPath) { $ImportPath = "$ScriptDir\OU_Structure.csv" }
    if (-not $UpdatePath) { $UpdatePath = "$ScriptDir\Updated_OU_Structure.csv" }
    if (-not $LogPath) { $LogPath = "$ScriptDir\OU_Migration.log" }

    if (-Not (Test-Path $ImportPath)) {
        Write-Host "[Failed] CSV file not found: $ImportPath" -ForegroundColor Red
        Write-Log -Message "[Failed] CSV file not found: $ImportPath" -LogPath $LogPath
        return
    }

    $OUs = Import-Csv -Path $ImportPath

    # Sort by hierarchy depth to ensure parent OUs are created first
    $OUs = $OUs | Sort-Object {($_.DistinguishedName -split ",").Count}

    # get SourceRootOU ParentOU
    $SourceRootOUParentOU = $OUs[0].ParentOU


    foreach ($OU in $OUs) {
        $OUName = $OU.Name
        $ParentOU = if ($TargetRootOU -ne "") { $OU.ParentOU -replace $SourceRootOUParentOU, $TargetRootOU } else { $OU.ParentOU }
        $OUPath = "OU=$OUName,$ParentOU"

#region Expression of popule Targe OU Pobject Path. # this csv colume will be used by ADMT.exe parameter /TO: (Value sample: x_oMG.org/migrated from omygu.com/migrate1)
        
        # get Target OU Object Path, the Path NOT included Domain Name Path
        $tOuPathArray = $null
        $tOuPathArray = ($OU.DistinguishedName -replace $SourceRootOUParentOU, $TargetRootOU) -split "," | Where-Object {$_ -notlike "DC=*"}
        $tOuPathArray = $tOuPathArray | ForEach-Object {$_ -replace "OU=", ""}
        $TargetOUPath = $null
        $TargetOUPath = $tOuPathArray[-1..-($tOuPathArray.Count)] -join "/"
#endregion

        # Check if the OU already exists
        if (-Not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction SilentlyContinue)) {
            Try {
                $OU.TargetOUPath = $TargetOUPath
                New-ADOrganizationalUnit -Name $OUName -Path $ParentOU -ProtectedFromAccidentalDeletion ([Boolean]$OU.ProtectedFromAccidentalDeletion) -ErrorAction Stop
                $OU.OuMigrated = "Success"
                Write-Host "[Successfully] OU: $OUPath" -ForegroundColor Green
                Write-Log -Message "[Successfully] created OU: $OUPath" -LogPath $LogPath
            } Catch {
                Write-Host "Failed to create OU: $OUPath - $_" -ForegroundColor Red
                Write-Log -Message "Failed to create OU: $OUPath - $_" -LogPath $LogPath
                $OU.OuMigrated = "Failed"
            }
        } else {
            Write-Host "[Warning] OU already exists: $OUPath" -ForegroundColor Yellow
            Write-Log -Message "[Warning] OU already exists: $OUPath" -LogPath $LogPath
            $OU.OuMigrated = "$($OU.OuMigrated);Skipped"
        }
    }

    $OUs | Export-Csv -Path $UpdatePath -NoTypeInformation -Encoding UTF8 -Force

}
