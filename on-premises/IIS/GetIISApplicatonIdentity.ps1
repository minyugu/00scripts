#v0.1

$iisServers = @("iis1.sae.com.hk";"iis2.sae.com.hk")
$iisApplicationPools = @{}
foreach ($iisServer in $iisServers)
{
    $iisApplicationPools += Invoke-Command -ComputerName $iisServer -Credential $cred -ScriptBlock {  
        Import-Module WebAdministration
        $iisApplicationPools = ""
        $iisApplicationPools = Get-ChildItem IIS:AppPools | Select-Object  @{L="ServerName"; E={$env:ComputerName}}, Name, $_.processModel.userName
        return $iisApplicationPools
    }
}

$iisApplicationPools