$stopAfter = 10
$fileSize = "100M"

$parameters = @{
    ComputerName = 'odaws.sha.corp.omygu.com'
    ScriptBlock  = {
        Param ($param1, $param2)
        $command = "`"C:\Program Files\Microsoft Network Monitor 3\NMCap.exe`" /network * /capture `"tcp.port == 445 && IPv4.Address == 172.30.11.11`" /startwhen /timeafter 1 /stopwhen /timeafter $param1 /file `"c:\tmp.cap:$param2`""
        cmd /c $command
    }
    ArgumentList = $stopAfter, $fileSize
}
$job = Invoke-Command @parameters -AsJob