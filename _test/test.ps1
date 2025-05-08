<#
# for test purposes only
# This script is used to find the maximum value of msNPSequence in an XML file

[xml]$xml = Get-Content -Path "C:\00scripts\on-premises\NPS\ias.xml" -Encoding UTF8


$maxValue = $xml.SelectNodes("/Root/Children/Microsoft_Internet_Authentication_Service/Children/NetworkPolicy/Children") | 
    ForEach-Object { $_.GetElementsByTagName("msNPSequence") } |
    Where-Object { $_ -ne $null } |
    ForEach-Object { [int]$_.InnerText } |
    Measure-Object -Maximum

$maxValue.Maximum.ToString()


$policyNameNew = "拒绝MAC_20250429163138"

$networkXPath = "/Root/Children/Microsoft_Internet_Authentication_Service/Children/NetworkPolicy/Children"

$ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$ns.AddNamespace("dt", "urn:schemas-microsoft-com:datatypes")

$enabledNode = $xml.SelectSingleNode("$networkXPath/Test_deny[@name='$policyNameNew']/Properties/Policy_Enabled", $ns)

if ($null -ne $enabledNode -and $enabledNode.InnerText -eq "0") {
    $enabledNode.InnerText = "1"
}
#>
function Get-macAndEnable {
    $cleanMAC = "1122-1122-1122"
    #region [mg] find the network policy with specific mac
    $macExisted = $false
    $networkPolicys = $xml.SelectNodes($networkXPath)
    foreach ($networkPolicy in $networkPolicys) {
        foreach ($npEnum in $networkPolicy.GetEnumerator() ) {
            $npEnum.GetElementsByTagName("msNPConstraint") | Where-Object { $null -ne $_ } | ForEach-Object {
                if ($_.InnerText.trim() -eq "MATCH(`"Calling-Station-Id=$cleanMAC`")") {
                    $npEnum.GetElementsByTagName("Policy_Enabled") | Where-Object { $null -ne $_ } | ForEach-Object {
                        if ($_.InnerText.trim() -eq "0") {
                            $_.InnerText = "1"
                        }
                    }
                    $macExisted = $true
                    break
                }
            }
        }
    }
    if ($macExisted -eq $false) {
 
    }
    #endregion
    $xml.Save("C:\00scripts\on-premises\NPS\ias.xml")
}

# get windows event log - Security-nps, Event ID 6273, check mac in 'Client Machine:' / 'Calling Station Identifier:'. if the mac repeat 3 times in last 10 mins, then add the mac to a string array for future use. 
# here is the mac sample for coding referrence: 'Calling Station Identifier:		4c5f-705d-f444'

# Define the event log parameters
$logName = "Security"
$eventID = 6273
$timeSpan = (Get-Date).AddMinutes(-10) # Last 10 minutes
$maxEvents = 5000 # Maximum number of events to retrieve

# Get the OS language code
$osLanguage = (Get-WmiObject -Class Win32_OperatingSystem).OSLanguage

# Use a switch statement to check the language to determine the correct field names
# 1033 for English, 2052 for Simplified Chinese
$clientMacField = ""
$npNameField = ""
switch ($osLanguage) {
    1033 { $clientMacField = "Calling Station Identifier:"; $npNameField = "Network Policy Name:" } # 1033 = English (US)
    2052 { $clientMacField = '调用站标识符:'; $npNameField = "网络策略名称:" } # 2052 = Chinese (Simplified)
    default { $clientMacField = "Calling Station Identifier:"; $npNameField = "Network Policy Name:" } # Default to English if unknown language}
}

# Initialize an empty hashtable to track MAC occurrences
$macOccurrences = @{}

# Get the relevant events from the Windows Event Log
$events = Get-WinEvent -FilterHashtable @{Id = $eventID; StartTime = $timeSpan; LogName = $logName} -MaxEvents $maxEvents -ErrorAction SilentlyContinue
$events = Get-WinEvent -FilterHashtable @{Id = $eventID; Path = "C:\Users\odacol\Desktop\Security.evtx"} -MaxEvents $maxEvents
if ($events.count -gt 0){
    Write-Host "Found $($events.count) events in the last 10 minutes."
    foreach ($event in $events) {
        # Extract the message from the event
        $message = $event.Message

        # check whether the mac already have been block by a nps policy
        # Use regex to check if the message includes "Network Policy Name:" followed by "-" -- meaning no policy enabled
        if ($message -match "$($npNameField)\s+-") {
            # Use regex to find the MAC address in the "Calling Station Identifier" field
            if ($message -match "$($clientMacField)\s+([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})") {
                $mac = $matches[1] # Extract the MAC address
        
                # Increment the occurrence count for the MAC address
                if ($macOccurrences.ContainsKey($mac)) {
                    $macOccurrences[$mac]++
                } else {
                    $macOccurrences[$mac] = 1
                }
            }
        }
    }
    
    # Filter MAC addresses that appear 3 or more times
    $frequentMACs = $macOccurrences.GetEnumerator() | Where-Object { $_.Value -ge 3 } | ForEach-Object { $_.Key }
} else {
    Write-Host "No events found in the last 10 minutes."
    exit 0 # exit if no events were found
}


# Check if any MAC addresses were found that repeated 3 or more times in the last 10 minutes
if ($frequentMACs.Count -gt 0) {
    Write-Host "$($frequentMACs.Count) MAC addresses(misses nps policy) that repeated 3 or more times in the last 10 minutes:"
    $frequentMACs | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No MAC addresses repeated 3 or more times in the last 10 minutes."
    exit 0 # exit if no MACs were found
}






"拒绝MAC_$($cleanMAC)_$(Get-Date -Format 'yyyyMMddHHmmss')"




foreach ($npEnum in $networkPolicy.GetEnumerator() ) {
    $npEnum.GetElementsByTagName("msNPConstraint") | Where-Object { $null -ne $_ } | ForEach-Object {
        $_.InnerText.trim();
        $npEnum.GetElementsByTagName("Policy_Enabled") | Where-Object { $null -ne $_ } | ForEach-Object {
                $_.InnerText.trim();
            }
        }
}
