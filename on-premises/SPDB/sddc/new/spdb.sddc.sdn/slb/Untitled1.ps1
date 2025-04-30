#$credential = Get-Credential
#Invoke-RestMethod "https://poc04ncfc.poc04.spdbcl.com/networking/v1/PublicIpAddresses" -Credential $credential -UseBasicParsing


#Invoke-RestMethod "https://poc04ncfc.poc04.spdbcl.com/networking/v1/PublicIpAddresses" -UseDefaultCredentials | ConvertTo-Json

10.145.138.129:1048

Import-Module "C:\Users\zhangpl\Desktop\slb\Get-VipConnectivityInfoMG.psm1" -Force

$VipResources = Get-NetworkControllerVipResourceMG -RestURI 'https://poc02ncfc.poc02.spdbcl.com' -IPAddress 10.145.138.129 -DstPort 22 -Protocol Tcp

Get-NetworkControllerVipResourceMG -RestURI 'https://poc02ncfc.poc02.spdbcl.com' -IPAddress 10.145.145.178 -DstPort 80 -Protocol Tcp

$VipHostMappings = Get-VipHostMappingMG -NetworkController 'poc01nc04.poc01.spdbcl.com' -RestURI 'https://poc02ncfc.poc02.spdbcl.com' -VipEndPoint ($VipResources.ResourceRef) -Type L3Nat

$VipResources.ResourceRef

$VipHostMappings.DIPHosts.portprofile.GetType()

Invoke-RestMethod "https://poc02ncfc.poc02.spdbcl.com/networking/v1/PublicIpAddresses/451ac9f3-c92e-4b7b-9253-da23b68f92a2" -UseBasicParsing -UseDefaultCredentials