
$account = "SREAssist"
$newpwd = "u78iU&*Iu78i"
$memberOf =”SCVMM Admins"
$sourceFile = "start-tools-SREAssist.ps1"
$sourceFilebak = "start-tools.bak-SREAssist.ps1"
$SoureFilePath ="D:\Alice\new-starttoolforSREreader\new-starttoolforSREreader\$sourceFile"
$SoureFilePathbak ="D:\Alice\new-starttoolforSREreader\new-starttoolforSREreader\$sourceFilebak"
$TargetLnk ="start-tools-SREAssist.lnk"
$ShortcutLocation = "C:\Users\SREReader\Desktop\$TargetLnk"

$Tier1Cred =New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($env:USERdomain)\tier1admin",("密码"|ConvertTo-SecureString -AsPlainText -Force)
$Tier0Cred =New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($env:USERdomain)\administrator",("密码"|ConvertTo-SecureString -AsPlainText -Force)



# New ADUser(T1)
$MasterDCName=dsquery server -o rdn -forest -hasfsmo schema
icm $MasterDCName {

        $account =$args[0]
        $newpwd =$args[1]
        $memberOf =$args[2]
        $newpwdString =ConvertTo-SecureString -AsPlainText $newpwd -Force
        New-ADUser -Name $account -AccountPassword $newpwdString -PasswordNeverExpires $true
        Enable-ADAccount -Identity $account
        Add-ADGroupMember -Identity $memberOf -Members $account
        
        Set-ADAccountPassword -NewPassword $newpwdString -Identity $account
    
    } -ArgumentList $account, $newpwd, $memberOf  -Credential $Tier0Cred 

Write-Host "$account created successfully!" -ForegroundColor Green

#Add new ADUser to local administrators (administrator)
$server = gc D:\Alice\new-starttoolforSREreader\new-starttoolforSREreader\Servers.txt 
$todoList =@()
$server | %{


        $temphostname=$_
        $tempObject =[pscustomobject]@{

            server =$temphostname
            account ="SREAssist"
            SoureFilePath =$SoureFilePath
            ShortcutLocation = $ShortcutLocation


                
        }
     
                $todoList +=$tempObject
          


        }
$todoList | %{
        $tempObject = $_
        icm $tempObject.server {
            $tempObject=$args[0]
            Add-LocalGroupMember -Name "Administrators" -Member $tempObject.account
            
        } -ArgumentList $tempObject -Credential $Tier1Cred
 
    }


#---------------------------------------------
#使用 PowerShell 创建快捷方式(administrator)
#Grap the pwd
$location = Get-Location | Select Path | ft -HideTableHeaders | Out-String;
#Trim the pwd variable of any extra spaces and unwanted characters
$location = $location.Trim();
$locations = $location.replace(' ' , '');
$locations = $locations.replace("`n","");

#Make the source file location my path to powershell.exe
$SourceFileLocation = "`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`""

# Declare where I want to place the shortcut, I placed it on the desktop of whomever is running the script with the dynamic $env:USERNAME which takes the username of whomever is running the script - You can name the shortcut anything you want at the end as long as it ends with .LNK
$ShortcutLocation = "C:\Users\SREReader\Desktop\$TargetLnk"

#Create a now com
$WScriptShell = New-Object -ComObject WScript.Shell

#create shortcut and provide the location parameter as an argument
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation)

#set the target path
$Shortcut.TargetPath = $SourceFileLocation

#Add arguments that will bypass the execution policy as well as provide a path to the source powershell script (make sure that the entire argument has double quotes around it and that the internal quotes have escape characters (`) behind them, these are not apostrophes but back ticks, located on the same key as the tilde (~) key on the keyboard
$Shortcut.Arguments = "$locations\$sourceFile"

#Save the Shortcut
$Shortcut.Save()

$wshell = New-Object -ComObject Wscript.Shell

$wshell.Popup("Operation Completed",0,"Done",0x1)

Write-Host "Shortcut $ShortcutLocation created successfully!" -ForegroundColor Green
#-------------------------------------------------------------

#远程复制文件(include PS1 and Shortcut)-T1
$todoList | %{
        $tempObject = $_
        $session1 = New-PSSession -ComputerName $tempObject.server
        Copy-Item -Path $tempObject.SoureFilePath -ToSession $session1 -Destination 'C:\Windows\System32'
        
        $session2 = New-PSSession -ComputerName $tempObject.server
        Copy-Item -Path $ShortcutLocation -ToSession $session2 -Destination 'C:\Users\SREReader\Desktop' -Force 

        $session3 = New-PSSession -ComputerName $tempObject.server
        Copy-Item -Path $SoureFilePathbak -ToSession $session3 -Destination 'C:\Windows\System32'
    }
Write-Host "Copy Files successfully!" -ForegroundColor Green
#-------------------------------------------------------------   


