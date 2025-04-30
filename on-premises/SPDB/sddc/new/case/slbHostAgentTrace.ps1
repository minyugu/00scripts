Import-Module C:\log\AzsHci.Networking.Sdn\AzsHci.Networking.Sdn.psd1
$sdnHosts = @("AZ-POC04-WC001.poc04.spdbcl.com")
Start-SdnHostTrace -SdnHosts $sdnHosts

Stop-SdnHostTrace -SdnHosts $sdnHosts
Start-SdnLogCollection -NcVMName "POC04NC05.poc04.spdbcl.com" -SdnHosts $sdnHosts -Role NC