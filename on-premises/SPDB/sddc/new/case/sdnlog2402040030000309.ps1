############start###############################
Import-Module C:\AzsHci.Networking.Sdn\AzsHci.Networking.Sdn.psd1

$infraInfo = Get-SdnInfraInfo -NcVMName POC04NC04
$sdnHosts = @("POC04NC04.poc04.spdbcl.com")
Start-SdnHostTrace -SdnHosts $sdnHosts


############stop###############################

Stop-SdnHostTrace -SdnHosts $sdnHosts
Start-SdnLogCollection -NcVMName POC04NC04 -SdnHosts $sdnHosts -Role NC,HyperV



#***************************************************************************

<##

$infraInfo = Get-SdnInfraInfo -NcVMName POC04NC05

$sdnHosts = @("poc04nc05.poc04.spdbcl.com")
Start-SdnHostTrace -SdnHosts $sdnHosts


###########################################

Stop-SdnHostTrace -SdnHosts $sdnHosts
Start-SdnLogCollection -NcVMName POC04NC05 -SdnHosts $sdnHosts -Role NC,HyperV


##>