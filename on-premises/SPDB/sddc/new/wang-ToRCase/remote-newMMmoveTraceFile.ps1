############ Remote##########################
if(!$cred) { $cred = Get-Credential poc01\ms-mygu }

### auto receive
$destComputer = "POC01VMM01"

### move trace file net_netio$_.etl && smbserver$_.etl
# mount SMBTracelog: driver with credential
$destComputerCshare = "\\" + $destComputer + "\c$"
if (!(Test-Path "SMBTracelog:\"))
 {
    New-PsDrive -PSProvider "Filesystem" -Root $destComputerCshare -Credential $cred -Name "SMBTracelog"
}

# create folder
$destPathwithHostName = "SMBTracelog:\01smbtraclog\" + $env:COMPUTERNAME
if (!(Test-Path $destPathwithHostName)) { New-Item -Path $destPathwithHostName -ItemType Directory }
                    
# get first log file
$sourceFileNames = @("D:\net_netio*.etl", "D:\smbserver*.etl")
foreach ($sourceFileName in $sourceFileNames) { $logs += Get-Item $sourceFileName }
$sourceLogFile = ($logs | sort LastWriteTime | select -First 1)
        
# move log
$sourceLogFile | Move-Item -Destination $destPathwithHostName