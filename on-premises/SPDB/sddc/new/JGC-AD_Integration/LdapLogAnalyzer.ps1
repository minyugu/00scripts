function Analyse-LdapLog
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$evtxFile,

        [Parameter(Mandatory=$False)]
        [ValidateSet('ID','Time','IP','','User','BindType')]
        [String[]]$RemoveDuplicateProperty
        )

    BEGIN
    {
        Write-Debug "BEGIN: Initializing settings"

        #stats
        $nTotalSuccess = 0      # No of lines of interest and saved with SUCCESS
        $nTotalFailed = 0       # No of lines of interest but FAILED to save

        $2889returnSelect = @{label="ID";expression={"2889"}}, 
                            @{label="Time";expression={$EventTime.toString()}},
                            @{label="IP";expression={($eventData[0].split(":"))[0]}},
                            @{label="User";expression={$eventData[1]}},
                            @{label="BindType";expression={$eventData[2]}}
        
        $1138returnSelect = @{label="ID";expression={"1138"}}, 
                            @{label="Time";expression={$EventTime.toString()}},
                            @{label="IP";expression={($eventData[2].split(":"))[0]}},
                            @{label="User";expression={$eventData[1]}},
                            @{label="BindType";expression={$null}}

        $HashTable = @{}
    }

    PROCESS
    {
        #searching for event 2889
        Get-WinEvent @{Path=$evtxFile;Id=2889,1138} | ForEach-Object -Process {
            # Convert the event to XML           
            #see https://docs.microsoft.com/de-de/archive/blogs/ashleymcglone/powershell-get-winevent-xml-madness-getting-details-from-event-logs
            Try
            {
                $eventData = ([xml]$_.ToXml()).Event.EventData.Data
                #getting timestamp
                $EventTime = ($_.TimeCreated)
                #getting user from eventlog

                if ($_.Id -eq 2889)
                {
                    $returnSelect = $2889returnSelect
                }
                elseif ($_.Id -eq 1138)
                {
                    $returnSelect = $1138returnSelect
                }

                if ( ($RemoveDuplicateProperty -eq $null) )
                {
                    $true | Select-Object $returnSelect
                }
                else
                {
                    $ldapRecord = $null
                    $ldapRecord = $true | Select-Object $returnSelect
                    $duplicatePropertyFound = $ldapRecord | Process-HashTable -hashTable $HashTable -KeyProperty $RemoveDuplicateProperty -onlyKey
                    if ($duplicatePropertyFound -eq $False)
                    {
                        $ldapRecord
                    }
                }

                $nTotalSuccess++
            }
            Catch
            {
                # Lines of Interest but FAILED to save
                Write-Debug "Failed to process row: $_"
                $nTotalFailed++
            } #end catch
        }
    }
}

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