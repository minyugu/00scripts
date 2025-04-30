Import-Module .\Get-DNSDebugLog.ps1 -Force

Get-DNSDebugLog -DNSLog ".\logs\35.log" | Export-Csv ".\35.csv"
Get-DNSDebugLog -DNSLog ".\logs\35.log" -RemoveDuplicateProperty Client







$line = "2024/12/2 15:51:54 166C PACKET  000001AB5710F890 UDP Rcv 10.191.24.4     c6b8   Q [0001   D   NOERROR] A      (14)esfregbiza2-sh(3)rel(4)spdb(3)com(0)"

$line = "05/03/2019 16:05:31 0F9C PACKET  000000082A8141F0 UDP Snd 10.202.168.232  c1f8 R Q [8081   DR  NOERROR] A      (3)api(11)blahblah(3)com(0)"

$mgdnspattern = "^(?<log_date>([0-9]{1,2}.[0-9]{1,2}.[0-9]{2,4}|[0-9]{2,4}-[0-9]{2}-[0-9]{2})\s*[0-9: ]{7,8}\s*(PM|AM)?) ([0-9A-Z]{3,4} PACKET\s*[0-9A-Za-z]{8,16}) (?<protocol>UDP|TCP) (?<way>Snd|Rcv) (?<ip>[0-9.]{7,15}|[0-9a-f:]{3,50})\s*([0-9a-z]{4}) (?<QR>.) (?<OpCode>.) \[.*\] (?<QueryType>.*) (?<query>\(.*)"

$mgdnspattern = "^(?<log_date>([0-9]{2,4}.[0-9]{1,2}.[0-9]{1,2}|[0-9]{1,2}.[0-9]{1,2}.[0-9]{2,4}|[0-9]{2,4}-[0-9]{2}-[0-9]{2})\s*[0-9: ]{7,8}\s*(PM|AM)?) ([0-9A-Z]{3,4} PACKET\s*[0-9A-Za-z]{8,16}) (?<protocol>UDP|TCP) (?<way>Snd|Rcv) (?<ip>[0-9.]{7,15}|[0-9a-f:]{3,50})\s*([0-9a-z]{4}) (?<QR>.) (?<OpCode>.) \[.*\] (?<QueryType>.*) (?<query>\(.*)"

$mgmatch = [regex]::match($line,$mgdnspattern) #approach 2
$mgmatch.Success



$outObj = [PSCustomObject]@{aa='33';bb='value'}

function changeObject
{
    Param ($obj)

    Write-Host $outObj
    $obj.aa = '10000'
    Write-Host $obj
    Write-Host $outObj
}

changeObject $outObj
Write-Host $outObj