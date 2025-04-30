# Administrator1 account
$privilegedAccountName = "Administrator1"

# srereader account
$unprivilegedAccountName = "SREreader"

# SREAssist account name
$SREAssistAccountName = "SREAssist"

# tir2 account name
$Tier1AdminAccountName = "tier1admin"

# Make the source file location my path to powershell.exe
$shortcutTrgetPath = "`"$($env:SystemRoot)\system32\WindowsPowerShell\v1.0\powershell.exe`""
$shortcutArg1 = "C:\StartTools\start-tools.ps1"

$shortcutCreateStartToolsShortcutePath = "create-StartToolsShortcute.lnk"

# determine user for preparing shortcut creating
if ( ($env:USERNAME) -eq $privilegedAccountName )
{

    $TargetLnk ="start-tools-$($Tier1AdminAccountName).lnk"
    $shortcutArgs = "$shortcutArg1 -runasAccountName $Tier1AdminAccountName"

} elseif ( ($env:USERNAME) -eq $unprivilegedAccountName )
{

    $TargetLnk ="start-tools-$($SREAssistAccountName).lnk"
    $shortcutArgs = "$shortcutArg1 -runasAccountName $SREAssistAccountName"

} else {
    Write-Host "no acceptable login user"
    if (Test-Path "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Startup\$($shortcutCreateStartToolsShortcutePath)") {
        Remove-Item "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Startup\$($shortcutCreateStartToolsShortcutePath)" -Force
    }
    Return
}


# Declare where I want to place the shortcut, I placed it on the desktop of whomever is running the script with the dynamic $env:USERNAME which takes the username of whomever is running the script - You can name the shortcut anything you want at the end as long as it ends with .LNK
$ShortcutLocation = "$([Environment]::GetFolderPath("Desktop"))\$TargetLnk"

#Create a now com
$WScriptShell = New-Object -ComObject WScript.Shell

#create shortcut and provide the location parameter as an argument
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation)

#set the target path
$Shortcut.TargetPath = $shortcutTrgetPath
$Shortcut.Arguments = $shortcutArgs

#Save the Shortcut
$Shortcut.Save()

# remove startup lnk file
if (Test-Path "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Startup\$($shortcutCreateStartToolsShortcutePath)") {
    Remove-Item "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Startup\$($shortcutCreateStartToolsShortcutePath)" -Force
}

$wshell = New-Object -ComObject Wscript.Shell

$wshell.Popup("StartTools Initial Comptleted",0,"Done",0)