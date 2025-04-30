#$csvPath = "D:\Users\c-gumy\My Document\script-new\JGC-AD_Integration\logs\csv\DEV-AD1TEMP"
#$csvPath = "D:\Users\c-gumy\My Document\script-new\JGC-AD_Integration\logs\csv\DEV-AD2"
$csvPath = "D:\Users\c-gumy\My Document\script-new\JGC-AD_Integration\logs\csv\UAT-AD2"

# process HashTable table
function Process-HashTable
{
	Param
	(
        [Parameter(Mandatory=$true)]
		[Hashtable]$HashTable,

		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[PsObject]$Object,

		[Parameter(Mandatory=$true)]
		[String[]]$KeyProperty,

		[Parameter(Mandatory=$false)]
		[Switch]$onlyKey=$false
	)

    $keyFound = $false

    $key = ($KeyProperty | ForEach-Object -Process {$Object.$_}) -join ','
	if (![string]::IsNullOrEmpty($key))
	{
        if ($HashTable.ContainsKey($key) -eq $false)
		{
            if ($onlyKey)
            {
                $HashTable.Add($key, $null)
            }
            else
            {
			    $HashTable.Add($key, $Object)
            }
		}
        else
        {
            $keyFound = $true
        }
	}
	return $keyFound
}

$RemoveDuplicateProperty = @('Client')
$HashTable = @{}

Get-ChildItem -Path $csvPath -File | ForEach-Object -Process {
    $serverName = $_.Directory.Name
    Import-Csv -Path $_.FullName | ForEach-Object -Process {
        
        $duplicatePropertyFound = $_ | Process-HashTable -hashTable $HashTable -KeyProperty $RemoveDuplicateProperty -onlyKey
        if ($duplicatePropertyFound -eq $False)
        {
            $_ | Export-Csv -Path "$($csvPath)\$($serverName).csv" -NoTypeInformation -Encoding UTF8 -Append
        }
    }
}
