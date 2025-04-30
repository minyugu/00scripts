param
(
    [Parameter(mandatory=$true)]
    [String]$runasAccountName
)

$ErrorActionPreference = "Stop"

# [mg] to add credential frist
$domainname = (Get-WmiObject -Namespace root\cimv2 -Class Win32_computersystem).domain
runas.exe /savecred /user:$($domainname)\$($runasAccountName)  "cmd.exe /c @echo check runas account"

[reflection.assembly]::loadwithpartialname("system.windows.forms") | Out-Null
[reflection.assembly]::loadwithpartialname("system.drawing") | Out-Null
$MainForm = New-Object windows.forms.form

Function Start
{
<#
    [CmdletBingding()]
    param(
        [Parameter(Mandatory=$True)]
        [string]$domainname
    )
#>
    $domainname = (Get-WmiObject -Namespace root\cimv2 -Class Win32_computersystem).domain
    if($CheckBoxVMMConsole.Checked){
        runas.exe /savecred /user:$($domainname)\$($runasAccountName)  "C:\Program Files\Microsoft System Center\Virtual Machine Manager\Bin\VmmAdminUI.exe"
    }
    if($CheckBoxPowershellISE.Checked){
        runas.exe /savecred /user:$($domainname)\$($runasAccountName)  "C:\windows\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"
    }
    if($CheckBoxPowershell.Checked){
        runas.exe /savecred /user:$($domainname)\$($runasAccountName)  "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
    }
    if($CheckBoxFailoverCluster.Checked){
        runas.exe /savecred /user:$($domainname)\$($runasAccountName)  "cmd /c Start /B mmc.exe Cluadmin.msc"
    }
    if($CheckBoxHyperVManager.Checked){
        runas.exe /savecred /user:$($domainname)\$($runasAccountName)  "cmd /c Start /B mmc.exe virtmgmt.msc"
    }  
}

# Start GUI
#region GUI

# Group 1
$GroupBoxList = New-Object System.Windows.Forms.GroupBox       #create the group box
$GroupBoxList.Location = New-Object System.Drawing.Size(20,15) #location of the group box (px) in relation to the primary window's edges (length, height)
$GroupBoxList.size = New-Object System.Drawing.Size(240,240)  #the size in px of the group box (length, height)
$GroupBoxList.text = "Select The Application"

$CheckBoxVMMConsole = New-Object windows.Forms.CheckBox
$CheckBoxVMMConsole.Location = New-Object System.Drawing.Size(30,40) 
$CheckBoxVMMConsole.Text = "VMM Console"
$CheckBoxVMMConsole.AutoSize = $true
$GroupBoxList.Controls.Add($CheckBoxVMMConsole) 

$CheckBoxPowershellISE = New-Object windows.Forms.CheckBox
$CheckBoxPowershellISE.Location = New-Object System.Drawing.Size(30,70) 
$CheckBoxPowershellISE.Text = "Powershell ISE"
$CheckBoxPowershellISE.Checked = $true
$CheckBoxPowershellISE.AutoSize = $true
$GroupBoxList.Controls.Add($CheckBoxPowershellISE) 

$CheckBoxPowershell = New-Object windows.Forms.CheckBox
$CheckBoxPowershell.Location = New-Object System.Drawing.Size(30,100) 
$CheckBoxPowershell.Text = "Powershell"
$CheckBoxPowershell.AutoSize = $true
$GroupBoxList.Controls.Add($CheckBoxPowershell)

$CheckBoxFailoverCluster = New-Object windows.Forms.CheckBox
$CheckBoxFailoverCluster.Location = New-Object System.Drawing.Size(30,130) 
$CheckBoxFailoverCluster.Text = "Failover Cluster"
$CheckBoxFailoverCluster.AutoSize = $true
$GroupBoxList.Controls.Add($CheckBoxFailoverCluster)

$CheckBoxHyperVManager = New-Object windows.Forms.CheckBox
$CheckBoxHyperVManager.Location = New-Object System.Drawing.Size(30,160) 
$CheckBoxHyperVManager.Text = "HyperV Manager"
$CheckBoxHyperVManager.AutoSize = $true
$GroupBoxList.Controls.Add($CheckBoxHyperVManager)  

$ButtonStart = New-Object windows.Forms.Button
$ButtonStart.Location = New-Object System.Drawing.Size(170,220) 
$ButtonStart.Size = New-Object System.Drawing.Size(80,20)
$ButtonStart.Text = "Start"
$ButtonStart.Add_Click($Function:Start);         
$GroupBoxList.Controls.Add($ButtonStart) 


# Mainform 
$MainForm.Controls.Add($CheckBoxVMMConsole)
$MainForm.Controls.Add($CheckBoxPowershellISE)
$MainForm.Controls.Add($CheckBoxPowershell)
$MainForm.Controls.Add($CheckBoxFailoverCluster)
$MainForm.Controls.Add($CheckBoxHyperVManager)
$MainForm.Controls.Add($ButtonStart)

$MainForm.Controls.Add($GroupBoxList)

<#
$base64 =""
$Iconstream = [System.IO.MemoryStream][System.Convert]::FromBase64String($base64)
$Iconbmp    = [System.Drawing.Bitmap][System.Drawing.Image]::FromStream($Iconstream)
$Iconhandle = $Iconbmp.GetHicon()
$Icon       = [System.Drawing.Icon]::FromHandle($Iconhandle)
#>

$MainForm.Size = New-Object system.drawing.size @(300,300);
$MainForm.Text = "Start Tools"
#$MainForm.Icon = $icon
$MainForm.StartPosition = "CenterScreen"
$MainForm.ShowDialog()|Out-Null
#endregion GUI

# End GUI