# srereader account
param
(
    [Parameter(mandatory=$false)]
    [String]$unprivilegedAccountName = "SREreader"
)

# ouput message
$invokeOutput = ""

$invokeOutput += "Start Create shortcut to Public Desktop ########## $(Get-date)`n"
# Make the source file location my path to powershell.exe
$shortcutTrgetPath = "`"$($env:SystemRoot)\system32\WindowsPowerShell\v1.0\powershell.exe`""
$shortcutArgs = "C:\StartTools\start-tools.ps1"

$shortcuPath = "$env:PUBLIC\Desktop"
$shortcutFileName = "start-tools-v2.lnk"

if (!(Test-Path -Path $shortcuPath))
{
    try {
        $invokeOutput += New-Item -Path "$shortcuPath" -ItemType Directory -ErrorAction Stop
        $invokeOutput += "`n"
    } catch {
        $invokeOutput += "Error::`n"
        $invokeOutput += $_
        $invokeOutput += "`n"
    }
}


# Declare where I want to place the shortcut, I placed it on the desktop of whomever is running the script with the dynamic $env:USERNAME which takes the username of whomever is running the script - You can name the shortcut anything you want at the end as long as it ends with .LNK
$ShortcutLocation = "$($shortcuPath)\$shortcutFileName"

#Create a now com
$WScriptShell = New-Object -ComObject WScript.Shell

#create shortcut and provide the location parameter as an argument
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation)

#set the target path
$Shortcut.TargetPath = $shortcutTrgetPath
$Shortcut.Arguments = $shortcutArgs

#Save the Shortcut
try {
    $Shortcut.Save()
} catch {
    $invokeOutput += "`nError::`n"
    $invokeOutput += $_
    $invokeOutput += "`n"
}
$invokeOutput += "Completed Create shortcut to Public Desktop ########## $(Get-date)`n"

$invokeOutput += "`n"


# add SREreader 'reader & execute' permission to Shortchut StrartTools
$invokeOutput += "Start add SREreader 'reader & execute' permission to Shortchut $ShortcutLocation ########## $(Get-date)`n"

try {
    $AllowUnprivilegedAccountAcl = New-Object System.Security.AccessControl.FileSystemAccessRule($unprivilegedAccountName,"ReadAndExecute","Allow")
    $DUPAA = (get-Acl $ShortcutLocation -ErrorAction stop)
    $DUPAA.AddAccessRule($AllowUnprivilegedAccountAcl)
    Set-Acl $ShortcutLocation -AclObject $DUPAA -ErrorAction Stop
} catch {
    $invokeOutput += "Error::`n"
    $invokeOutput += $_
    $invokeOutput += "`n"
}
$invokeOutput += "Completed add SREreader 'reader & execute' permission to Shortchut $ShortcutLocation ########## $(Get-date)`n"
$invokeOutput += "`n"

return $invokeOutput