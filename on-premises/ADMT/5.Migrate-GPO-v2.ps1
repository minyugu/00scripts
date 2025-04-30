$folderPath = "D:\万科域控GPO-20250217"  # Change this to your root directory
$domainDN = "DC=onewo,DC=net,DC=cn"
$csvFile = "D:\万科域控GPO-20250217\gpoLink.csv"

<#
$files = Get-ChildItem -Path $folderPath -Filter "gpreport.xml" -Recurse -File

$results = @()  # Initialize an empty array to store results

foreach ($file in $files)
{
    [xml]$xml = Get-Content $file.FullName -Encoding UTF8
    
    $gpoName = $xml.GPO.Name
    $gpoLinks = $xml.GPO.LinksTo.SOMPath
    
    if ($gpoLinks -isnot [array] -and (-not [String]::IsNullOrEmpty($gpoLinks)))
    {
        $gpoLinks = @($gpoLinks)
    }
    #Write-Host $gpoLinks
#    Write-Host "`n============================"
#    $gpoName
#    $gpoLinks
    $mGPLink = ""
    $newGPLinks = @()
    $gpoLinks | ForEach-Object -Process {
        if (-not [String]::IsNullOrEmpty($_))
        {
            $mGPLink = ($_.trim()) -replace "vanke.net.cn/", ""
            $GpOuArray = $mGPLink -split "/"
            $mGPLink = $GpOuArray[-1..-($GpOuArray.count)] -join ",OU="
            $mGPLink = "OU=$($mGPLink),$($domainDN)"
            $newGPLinks += $mGPLink
            Write-Host $mGPLink
        }
    }

    $obj = [PSCustomObject]@{
        FilePath = $file.FullName
        Name     = $gpoName
        SOMPath  = $gpoLinks -join ";"
        newSOMPath = $newGPLinks -join ";"
    }
    $results += $obj
}

$results | Export-Csv -Encoding UTF8 -Path $csvFile -NoTypeInformation
#>


$csvResults = Import-Csv -Path $csvFile
foreach ($gpo in $csvResults)
{
    Write-Host "Starting create GPO: $($gpo.Name)" -ForegroundColor Gray
    $newGPO = $null
    $newGPO = Import-GPO -BackupGpoName $gpo.Name -Path $folderPath -TargetName $gpo.Name -CreateIfNeeded -WhatIf
    Write-Host "Success created GPO: $($gpo.Name)" -ForegroundColor Green
    $newGpoLinks = $null
    if(-not [String]::IsNullOrEmpty($gpo.newSOMPath))
    {
        $newGpoLinks = $gpo.newSOMPath -split ";"

        foreach ($link in $newGpoLinks)
        {
            if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($link)'" )
            {
                $newGPO | New-GPLink -Target $link -LinkEnabled No -WhatIf
                Write-Host "Add GPO link to OU: $link" -ForegroundColor DarkGreen
            }
            else
            {
                Write-Host "[Error] Add GPO link, OU NOT exist: $link" -ForegroundColor Red
            }

        }
    }
}

