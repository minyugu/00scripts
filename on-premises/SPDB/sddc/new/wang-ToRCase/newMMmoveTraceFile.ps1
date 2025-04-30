$sourceComputer = "AZ-POC01-WC002" 
$ComputerSession = New-PSSession -ComputerName $sourceComputer #-Credential $cred
Enter-PSSession -Session $ComputerSession



Exit
Remove-PSSession $ComputerSession
