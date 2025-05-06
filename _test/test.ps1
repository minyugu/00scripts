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

